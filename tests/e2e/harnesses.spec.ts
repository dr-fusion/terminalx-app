import { test, expect } from "@playwright/test";

/**
 * E2E for Issue #4 — Provider/harness registry + OpenCode.
 *
 * Exercises the real Harnesses settings surface and the registry-driven
 * harness selector in the new-session dialog. The UI reads GET /api/harnesses
 * (registry + status probe), so these assertions cover the full client+server
 * path. Run later in integration (no server runs inside the worktree).
 */

test.describe("Harnesses settings page", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/settings");
    // Settings is a dedicated full-page view with a left nav; the Harnesses
    // section lives behind its nav item now (Conductor parity).
    await expect(page.getByTestId("settings-shell")).toBeVisible();
    await page.getByTestId("settings-nav-harnesses").click();
    await expect(page.getByTestId("harness-tabs")).toBeVisible();
  });

  test("renders the four configurable harness tabs with OpenCode marked NEW", async ({ page }) => {
    // bash is intentionally not a configurable harness tab; the four are
    // Claude Code / Codex / Cursor / OpenCode.
    await expect(page.getByTestId("harness-tab-claude")).toContainText("Claude Code");
    await expect(page.getByTestId("harness-tab-codex")).toContainText("Codex");
    await expect(page.getByTestId("harness-tab-cursor")).toContainText("Cursor");
    await expect(page.getByTestId("harness-tab-opencode")).toContainText("OpenCode");

    // OpenCode carries the NEW badge.
    await expect(page.getByTestId("harness-badge-opencode")).toBeVisible();
    await expect(page.getByTestId("harness-badge-opencode")).toHaveText(/new/i);
  });

  test("Claude Code tab shows auth choice, status pill, account table, and Run login", async ({
    page,
  }) => {
    await page.getByTestId("harness-tab-claude").click();
    await expect(page.getByTestId("harness-panel-claude")).toBeVisible();

    // CLI vs API-key choice.
    await expect(page.getByTestId("harness-auth-cli")).toBeVisible();
    await expect(page.getByTestId("harness-auth-api-key")).toBeVisible();

    // Connected / Not-installed pill.
    await expect(page.getByTestId("harness-status-pill")).toBeVisible();

    // Provider/Plan/Org/Account table (dashes when unknown — never fabricated).
    const table = page.getByTestId("harness-account-table");
    await expect(table).toBeVisible();
    await expect(table).toContainText("Provider");
    await expect(table).toContainText("Plan");
    await expect(table).toContainText("Org");
    await expect(table).toContainText("Account");

    // "Run claude /login" affordance.
    await expect(page.getByTestId("harness-run-login")).toContainText(/run claude \/login/i);
  });

  test("OpenCode tab shows Providers, Models, and the Advanced config block", async ({ page }) => {
    await page.getByTestId("harness-tab-opencode").click();
    await expect(page.getByTestId("opencode-panel")).toBeVisible();

    // Providers "0 configured" → Add your first provider.
    const providersRow = page.getByTestId("opencode-providers-row");
    await expect(providersRow).toContainText(/0 configured/i);
    await expect(page.getByTestId("opencode-add-provider")).toContainText(
      /add your first provider/i
    );

    // Models "0 selected".
    const modelsRow = page.getByTestId("opencode-models-row");
    await expect(modelsRow).toContainText(/0 selected/i);
    await expect(page.getByTestId("opencode-add-model")).toContainText(
      /add your first opencode model/i
    );

    // Advanced (collapsible) → install/version pill, Open in Finder, Refresh, exec path.
    await page.getByTestId("opencode-advanced-toggle").click();
    await expect(page.getByTestId("opencode-advanced")).toBeVisible();
    await expect(page.getByTestId("opencode-installed-pill")).toBeVisible();
    await expect(page.getByTestId("opencode-open-finder")).toBeVisible();
    await expect(page.getByTestId("opencode-refresh")).toBeVisible();

    const execPath = page.getByTestId("opencode-exec-path");
    await expect(execPath).toBeVisible();
    await expect(execPath).toHaveAttribute("placeholder", "/usr/local/bin/opencode");
    await expect(page.getByTestId("opencode-advanced")).toContainText(
      /leave empty to use the bundled version/i
    );
  });

  test("Providers picker modal lists the 7 featured rows and the 96 total", async ({ page }) => {
    await page.getByTestId("harness-tab-opencode").click();
    await page.getByTestId("opencode-add-provider").click();

    const modal = page.getByTestId("opencode-providers-modal");
    await expect(modal).toBeVisible();
    await expect(page.getByTestId("opencode-providers-search")).toBeVisible();

    // Exact canonical Conductor labels.
    await expect(modal).toContainText("OpenCode Go / OpenCode Zen");
    await expect(modal).toContainText("OpenAI");
    await expect(modal).toContainText("GitHub Copilot / GitHub Models");
    await expect(modal).toContainText("Anthropic");
    await expect(modal).toContainText("Google");
    await expect(modal).toContainText("Vercel AI Gateway");
    await expect(modal).toContainText("OpenRouter");

    // Footer total.
    await expect(page.getByTestId("opencode-providers-view-all")).toContainText(
      /view all providers \(96\)/i
    );

    // Does NOT invent ChatGPT/Gemini/Ollama as canonical rows.
    await expect(modal).not.toContainText(/chatgpt/i);
    await expect(modal).not.toContainText(/ollama/i);

    // Search narrows the list.
    await page.getByTestId("opencode-providers-search").fill("anthropic");
    await expect(page.getByTestId("opencode-provider-anthropic")).toBeVisible();
    await expect(modal).not.toContainText("OpenRouter");
  });

  test("Repo scope surfaces the Edit settings.toml affordance", async ({ page }) => {
    await page.getByTestId("harness-scope-repo").click();
    await expect(page.getByTestId("harness-edit-settings-toml")).toContainText(
      /\.terminalx\/settings\.toml/i
    );
  });
});

test.describe("new-session harness selector", () => {
  test("exposes every registry harness including Cursor and OpenCode[NEW]", async ({ page }) => {
    await page.goto("/dashboard");
    await page
      .getByRole("button", { name: /new session/i })
      .first()
      .click();

    const toggle = page.getByTestId("session-harness-toggle");
    await expect(toggle).toBeVisible();
    await expect(page.getByTestId("session-harness-bash")).toBeVisible();
    await expect(page.getByTestId("session-harness-claude")).toContainText("Claude Code");
    await expect(page.getByTestId("session-harness-codex")).toBeVisible();
    await expect(page.getByTestId("session-harness-cursor")).toBeVisible();
    await expect(page.getByTestId("session-harness-opencode")).toContainText("OpenCode");

    // LocalTmux sessions never expose skip-permissions controls, regardless of
    // which local harness is selected.
    await page.getByTestId("session-harness-claude").click();
    await expect(page.getByTestId("session-skip-permissions")).toHaveCount(0);

    await page.getByTestId("session-harness-codex").click();
    await expect(page.getByTestId("session-skip-permissions")).toHaveCount(0);
  });
});
