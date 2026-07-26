import { test, expect, type BrowserContext } from "@playwright/test";
import {
  uniqueSuffix,
  contextFor,
  submitCommand,
  createTeamSession,
  readSessionDetail,
  readAdmission,
  readAttention,
  markAttentionRead,
  whoami,
  type CreatedSession,
} from "./helpers";

/**
 * Phase 12 — hermetic local-auth multi-user Team Session E2E.
 *
 * Two real authenticated browser users (alice = admin/manager, bob = member) in
 * one Team Session, exercising: participant admission, the steering fence /
 * controller handoff, conversation + @mentions + the attention inbox, and the
 * operator error surface. Runs across Chromium, WebKit, and a mobile viewport
 * (see playwright.config.ts projects). Every mutation goes through the real
 * same-origin command bus the browser client uses; UI rendering is asserted on
 * real pages at each key point.
 */

test.describe.configure({ mode: "serial" });

test.describe("multi-user Team Session", () => {
  let alice: BrowserContext;
  let bob: BrowserContext;
  let bobUserId: string;
  let created: CreatedSession;
  const suffix = uniqueSuffix();

  test.beforeAll(async ({ browser }) => {
    alice = await contextFor(browser, "alice");
    bob = await contextFor(browser, "bob");
    bobUserId = await whoami(bob.request);

    created = await createTeamSession(alice.request, {
      team: `team-${suffix}`,
      project: `project-${suffix}`,
      session: `session-${suffix}`,
      steeringPolicy: "single",
    });
  });

  test.afterAll(async () => {
    await alice?.close();
    await bob?.close();
  });

  test("alice sees her new session in the dashboard/team-sessions UI", async () => {
    const page = await alice.newPage();
    await page.goto("/team-sessions");
    // The session inbox lists the freshly created session by name.
    await expect(page.getByText(`session-${suffix}`)).toBeVisible({ timeout: 15_000 });
    await page.close();
  });

  test("participant admission: invite → redeem/join (pending) → manager grants access", async () => {
    // Before admission, bob cannot read the session (existence not leaked → 404).
    const before = await bob.request.get(
      `/api/team-sessions/sessions/${encodeURIComponent(created.sessionId)}`
    );
    expect(before.status()).toBe(404);

    // alice invites a guest.
    const detail = await readSessionDetail(alice.request, created.sessionId);
    const invite = await submitCommand(alice.request, {
      type: "session.invitation.create",
      sessionId: created.sessionId,
      membershipRole: "guest",
      expiresAtMs: Date.now() + 60 * 60 * 1000,
      expectedAccessRevision: detail.viewer.basis.accessRevision,
    });
    const token = invite.data.invitationToken as string;
    expect(token).toBeTruthy();

    // bob redeems then joins — join is pending manager approval.
    const redeem = await submitCommand(bob.request, {
      type: "session.invitation.redeem",
      token,
    });
    const invitationId = redeem.data.invitationId as string;
    expect(invitationId).toBeTruthy();

    // Join before approval fails closed (verified-but-awaiting-grant).
    await expect(
      submitCommand(bob.request, {
        type: "session.join",
        sessionId: created.sessionId,
        invitationId,
      })
    ).rejects.toThrow();

    // alice approves the guest via a session share.
    const admission = await readAdmission(alice.request, created.sessionId);
    const candidate = admission.accessCandidates.find((c) => c.userId === bobUserId);
    expect(candidate, "bob should be in the admission queue").toBeTruthy();
    await submitCommand(alice.request, {
      type: "session.share.create",
      sessionId: created.sessionId,
      userId: bobUserId,
      expectedAccessRevision: admission.accessRevision,
    });

    // bob completes the join and can now read the session.
    await submitCommand(bob.request, {
      type: "session.join",
      sessionId: created.sessionId,
      invitationId,
    });
    const bobDetail = await readSessionDetail(bob.request, created.sessionId);
    expect(bobDetail).toBeTruthy();

    // bob's page opens the session workspace (no "couldn't open" error surface).
    const page = await bob.newPage();
    await page.goto(`/team-sessions/${encodeURIComponent(created.sessionId)}`);
    await expect(page.getByRole("heading", { name: /Couldn't open this session/i })).toHaveCount(0);
    await expect(page.getByRole("tab", { name: /Conversation/i })).toBeVisible({ timeout: 15_000 });
    await page.close();
  });

  test("conversation + @mention delivers to the mentioned user's attention inbox", async () => {
    const body = `Please take a look @${bobUserId} — checkout latency ${suffix}`;
    const comment = await submitCommand(alice.request, {
      type: "comment.add",
      sessionId: created.sessionId,
      body,
      attachments: [],
    });
    const sequence = comment.data.sequence as number;
    expect(typeof sequence).toBe("number");

    // bob's conversation surface renders the comment and the mention chip.
    const page = await bob.newPage();
    await page.goto(`/team-sessions/${encodeURIComponent(created.sessionId)}`);
    const conversationTab = page.getByRole("tab", { name: /Conversation/i });
    if (await conversationTab.isVisible().catch(() => false)) {
      await conversationTab.click();
    }
    await expect(page.getByText(`checkout latency ${suffix}`)).toBeVisible({ timeout: 15_000 });
    await expect(page.locator("[data-mention]").first()).toBeVisible();

    // The mention lands in bob's attention inbox as unread.
    const inbox = await readAttention(bob.request);
    const item = inbox.items.find((i) => i.sessionId === created.sessionId && i.kind === "mention");
    expect(item, "bob should have an unread mention").toBeTruthy();
    expect(item?.read).toBe(false);
    expect(inbox.unreadCount).toBeGreaterThan(0);

    // bob's inbox page shows the item; mark it read and confirm the count clears.
    await page.goto("/inbox");
    await expect(page.getByRole("heading", { name: "Attention inbox" })).toBeVisible();
    await expect(page.getByRole("list", { name: "Attention items" })).toBeVisible({
      timeout: 15_000,
    });

    await markAttentionRead(bob.request, created.sessionId, sequence);
    const after = await readAttention(bob.request);
    const stillUnread = after.items.find(
      (i) => i.sessionId === created.sessionId && i.kind === "mention" && !i.read
    );
    expect(stillUnread).toBeUndefined();

    await page.close();
  });

  test("steering fence: controller handoff bumps the control epoch and shifts capabilities", async () => {
    // Single-policy session: alice starts as controller/steerer, bob observes.
    const beforeAlice = await readSessionDetail(alice.request, created.sessionId);
    const beforeBob = await readSessionDetail(bob.request, created.sessionId);
    expect(beforeAlice.viewer.capabilities.mutateTerminal).toBe(true);
    expect(beforeBob.viewer.capabilities.mutateTerminal).toBe(false);
    const epochBefore = beforeAlice.viewer.basis.controlEpoch;

    // Find bob's participant version for the fence.
    const bobParticipant = beforeAlice.participants.find(
      (p) => (p as { userId?: string }).userId === bobUserId
    ) as { version?: number } | undefined;
    expect(bobParticipant, "bob should be an active participant").toBeTruthy();

    // alice transfers control to bob (the steering fence advances).
    await submitCommand(alice.request, {
      type: "session.control.transfer",
      sessionId: created.sessionId,
      userId: bobUserId,
      expectedControlRevision: beforeAlice.viewer.basis.controlRevision,
      expectedControlEpoch: epochBefore,
      expectedParticipantVersion: bobParticipant?.version ?? 0,
    });

    const afterAlice = await readSessionDetail(alice.request, created.sessionId);
    const afterBob = await readSessionDetail(bob.request, created.sessionId);
    // The steering fence (control epoch) is strictly advanced.
    expect(afterAlice.viewer.basis.controlEpoch).toBeGreaterThan(epochBefore);
    // Capability shifts: bob may now steer/mutate, alice no longer controls input.
    expect(afterBob.viewer.capabilities.mutateTerminal).toBe(true);
    expect(afterAlice.viewer.capabilities.mutateTerminal).toBe(false);
  });

  test("operator error states render a single non-leaking surface", async () => {
    const page = await bob.newPage();

    // A session that does not exist (or is access-denied) yields the same
    // non-leaking inline error — existence is never disclosed.
    await page.goto(`/team-sessions/does-not-exist-${uniqueSuffix()}`);
    await expect(page.getByRole("heading", { name: /Couldn't open this session/i })).toBeVisible({
      timeout: 15_000,
    });

    // An unmatched route renders the root 404 surface.
    await page.goto(`/this-route-does-not-exist-${uniqueSuffix()}`);
    await expect(page.getByRole("heading", { name: /This page doesn't exist/i })).toBeVisible({
      timeout: 15_000,
    });

    await page.close();
  });
});

/** The two seeded users are distinct canonical identities. */
test("local-auth server seeded two distinct users", async ({ browser }) => {
  const a = await contextFor(browser, "alice");
  const b = await contextFor(browser, "bob");
  const [aliceId, bobId]: [string, string] = [await whoami(a.request), await whoami(b.request)];
  expect(aliceId).not.toBe(bobId);
  await a.close();
  await b.close();
});
