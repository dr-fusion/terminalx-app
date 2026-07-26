import { test, expect, type Page } from "@playwright/test";
import * as fs from "node:fs";
import { uniqueSuffix, contextFor, createTeamSession, submitCommand, whoami } from "./helpers";

/**
 * Phase 12 — accessibility pass (completes the 11B a11y verification deferral).
 *
 * Runs axe-core (vendored from node_modules, injected into the page — no network,
 * no CDN) over the primary flows (login, dashboard, session detail, conversation,
 * inbox). This spec is included in the desktop (Chromium/WebKit) and mobile
 * viewport projects, so the primary flows are checked at desktop + mobile.
 *
 * We fail on serious/critical WCAG 2.0/2.1 A+AA violations. The xterm terminal
 * canvas is excluded (third-party imperative widget with its own a11y story).
 */

// axe-core is vendored in node_modules; inject its bundled source into the page
// (no network, no CDN — self-contained). Resolved via CommonJS require.resolve,
// which is available in Playwright's spec runtime.
const AXE_SOURCE = fs.readFileSync(require.resolve("axe-core"), "utf-8");

interface AxeViolation {
  id: string;
  impact: string | null;
  help: string;
  nodes: Array<{ target: string[]; failureSummary?: string }>;
}

async function seriousOrCriticalViolations(page: Page): Promise<AxeViolation[]> {
  await page.addScriptTag({ content: AXE_SOURCE });
  const result = (await page.evaluate(async () => {
    // @ts-expect-error axe is injected onto window at runtime
    return await window.axe.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] },
      // The terminal is a third-party canvas widget; exclude it from the scan.
      exclude: [['[data-testid="team-session-terminal"]']],
    });
  })) as { violations: AxeViolation[] };
  return result.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
}

function describeViolations(violations: AxeViolation[]): string {
  return violations
    .map(
      (v) =>
        `${v.id} (${v.impact}): ${v.help} — ${v.nodes
          .slice(0, 3)
          .map((n) => n.target.join(" "))
          .join(", ")}`
    )
    .join("\n");
}

test.describe("accessibility — primary flows", () => {
  test("login page has no serious/critical a11y violations", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
    const violations = await seriousOrCriticalViolations(page);
    expect(violations, describeViolations(violations)).toEqual([]);
  });

  test.describe("authenticated surfaces", () => {
    const suffix = uniqueSuffix();
    let alice: Awaited<ReturnType<typeof contextFor>>;
    let sessionId: string;

    test.beforeAll(async ({ browser }) => {
      alice = await contextFor(browser, "alice");
      const bob = await contextFor(browser, "bob");
      const bobUserId = await whoami(bob.request);

      const created = await createTeamSession(alice.request, {
        team: `a11y-team-${suffix}`,
        project: `a11y-project-${suffix}`,
        session: `a11y-session-${suffix}`,
      });
      sessionId = created.sessionId;

      // Seed a comment mentioning bob so the conversation + inbox have content.
      await submitCommand(alice.request, {
        type: "comment.add",
        sessionId,
        body: `Kickoff note for @${bobUserId} — ${suffix}`,
        attachments: [],
      });

      await bob.close();
    });

    test.afterAll(async () => {
      await alice?.close();
    });

    test("dashboard", async () => {
      const page = await alice.newPage();
      await page.goto("/dashboard");
      await page.waitForLoadState("networkidle");
      const violations = await seriousOrCriticalViolations(page);
      expect(violations, describeViolations(violations)).toEqual([]);
      await page.close();
    });

    test("team-sessions list + session detail + conversation", async () => {
      const page = await alice.newPage();

      await page.goto("/team-sessions");
      await page.waitForLoadState("networkidle");
      let violations = await seriousOrCriticalViolations(page);
      expect(violations, `team-sessions:\n${describeViolations(violations)}`).toEqual([]);

      await page.goto(`/team-sessions/${encodeURIComponent(sessionId)}`);
      const conversationTab = page.getByRole("tab", { name: /Conversation/i });
      await expect(conversationTab).toBeVisible({ timeout: 15_000 });
      await conversationTab.click();
      await page.waitForLoadState("networkidle");
      violations = await seriousOrCriticalViolations(page);
      expect(violations, `session-detail/conversation:\n${describeViolations(violations)}`).toEqual(
        []
      );

      await page.close();
    });

    test("attention inbox", async () => {
      const page = await alice.newPage();
      await page.goto("/inbox");
      await expect(page.getByRole("heading", { name: "Attention inbox" })).toBeVisible();
      await page.waitForLoadState("networkidle");
      const violations = await seriousOrCriticalViolations(page);
      expect(violations, describeViolations(violations)).toEqual([]);
      await page.close();
    });
  });
});
