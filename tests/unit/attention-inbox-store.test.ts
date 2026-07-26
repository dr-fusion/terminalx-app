import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { SESSION_EVENT_CHAIN_GENESIS } from "@/lib/team-sessions/session-event-chain";
import { AttentionInboxStore, AttentionInboxError } from "@/lib/attention/store";
import type { AttentionDeliveryDeps } from "@/lib/attention/contracts";

let seq = 0;
const nextId = () => `id-${(seq += 1)}`;

function fakeHash(sessionId: string, sequence: number): string {
  return createHash("sha256").update(`${sessionId}:${sequence}`).digest("hex");
}

const heads = new Map<string, string | null>();

function insertEvent(
  db: TeamSessionDatabase["db"],
  sessionId: string,
  sequence: number,
  type: string,
  actorUserId: string,
  occurredAtMs: number,
  payload: Record<string, unknown> = {}
): void {
  const prev = sequence === 1 ? SESSION_EVENT_CHAIN_GENESIS : (heads.get(sessionId) as string);
  const hash = fakeHash(sessionId, sequence);
  db.prepare(
    `INSERT INTO session_events
       (session_id, sequence, event_id, type, occurred_at_ms,
        actor_kind, actor_user_id, actor_display_name,
        source_scope, source_key, payload_json, prev_hash, hash)
     VALUES (?, ?, ?, ?, ?, 'human', ?, ?, 'test', ?, ?, ?, ?)`
  ).run(
    sessionId,
    sequence,
    `${sessionId}-event-${sequence}`,
    type,
    occurredAtMs,
    actorUserId,
    actorUserId,
    `${sessionId}-k-${sequence}`,
    JSON.stringify(payload),
    prev,
    hash
  );
  heads.set(sessionId, hash);
}

function seedSession(
  db: TeamSessionDatabase["db"],
  sessionId: string,
  options: { status?: string; teamId?: string; name?: string } = {}
): void {
  const teamId = options.teamId ?? "team-1";
  const projectId = `project-${teamId}`;
  db.prepare(`INSERT OR IGNORE INTO teams (id, name, created_at_ms) VALUES (?, 'Team', 1)`).run(
    teamId
  );
  db.prepare(
    `INSERT OR IGNORE INTO projects (id, team_id, name, created_at_ms) VALUES (?, ?, 'Project', 1)`
  ).run(projectId, teamId);
  db.prepare(
    `INSERT INTO sessions
       (id, team_id, project_id, name, status, steering_policy,
        runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
     VALUES (?, ?, ?, ?, ?, 'shared',
        'local-tmux', 'trusted-shared-host', ?, 0, 1)`
  ).run(
    sessionId,
    teamId,
    projectId,
    options.name ?? sessionId,
    options.status ?? "active",
    `${sessionId}-tmux`
  );
}

function addParticipant(
  db: TeamSessionDatabase["db"],
  sessionId: string,
  userId: string,
  status = "active"
): void {
  db.prepare(
    `INSERT INTO session_participants (id, session_id, user_id, status, version, joined_at_ms)
     VALUES (?, ?, ?, ?, 1, 1)`
  ).run(`${sessionId}-${userId}`, sessionId, userId, status);
}

function addResponsibility(
  db: TeamSessionDatabase["db"],
  sessionId: string,
  userId: string,
  kind: string
): void {
  db.prepare(
    `INSERT INTO session_responsibilities (session_id, user_id, kind, status, version, granted_at_ms)
     VALUES (?, ?, ?, 'active', 1, 1)`
  ).run(sessionId, userId, kind);
}

function addComment(
  db: TeamSessionDatabase["db"],
  sessionId: string,
  sequence: number,
  commentId: string,
  authorUserId: string,
  occurredAtMs: number
): void {
  insertEvent(db, sessionId, sequence, "comment.added", authorUserId, occurredAtMs, {
    commentId,
    body: "hello",
  });
  db.prepare(
    `INSERT INTO conversation_identities (id, session_id, kind, created_sequence, created_at_ms)
     VALUES (?, ?, 'comment', ?, ?)`
  ).run(commentId, sessionId, sequence, occurredAtMs);
}

function addMention(
  db: TeamSessionDatabase["db"],
  sessionId: string,
  commentId: string,
  commentSequence: number,
  mentionedUserId: string,
  authorUserId: string,
  createdAtMs: number
): void {
  db.prepare(
    `INSERT INTO comment_mentions
       (id, session_id, comment_id, comment_sequence, mentioned_user_id, author_user_id, created_at_ms)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    nextId(),
    sessionId,
    commentId,
    commentSequence,
    mentionedUserId,
    authorUserId,
    createdAtMs
  );
}

function addHandoff(
  db: TeamSessionDatabase["db"],
  sessionId: string,
  contextSequence: number,
  offererUserId: string,
  recipientUserId: string,
  expiresAtMs: number,
  createdAtMs: number
): void {
  db.prepare(
    `INSERT INTO session_handoffs
       (id, session_id, offerer_user_id, recipient_participant_id, recipient_user_id,
        offered_under_kind, offered_under_version, recipient_participant_version,
        base_assignee_revision, context_sequence, status, version, expires_at_ms,
        briefing_json, created_at_ms)
     VALUES (?, ?, ?, ?, ?, 'assignee', 1, 1, 1, ?, 'offered', 1, ?, '{}', ?)`
  ).run(
    `handoff-${sessionId}-${contextSequence}`,
    sessionId,
    offererUserId,
    `${sessionId}-${recipientUserId}`,
    recipientUserId,
    contextSequence,
    expiresAtMs,
    createdAtMs
  );
}

describe("AttentionInboxStore", () => {
  let database: TeamSessionDatabase | undefined;

  afterEach(() => {
    database?.close();
    database = undefined;
    heads.clear();
    seq = 0;
  });

  function open(): { db: TeamSessionDatabase["db"]; store: AttentionInboxStore } {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    const store = new AttentionInboxStore(database.db, {
      clock: () => 1_000,
      idGenerator: nextId,
    });
    return { db: database.db, store };
  }

  it("aggregates mentions across sessions and fences to active participants", () => {
    const { db, store } = open();
    // alice is a participant in session A (mentioned) and B (mentioned), but was
    // revoked from session C (must not surface).
    for (const s of ["A", "B", "C"]) seedSession(db, s);
    addParticipant(db, "A", "alice");
    addParticipant(db, "B", "alice");
    addParticipant(db, "C", "alice", "revoked");
    // The mention author must be an active participant to satisfy the FK; add one.
    addParticipant(db, "A", "bob");
    addParticipant(db, "B", "bob");
    addParticipant(db, "C", "bob");

    addComment(db, "A", 1, "comment-a", "bob", 100);
    addMention(db, "A", "comment-a", 1, "alice", "bob", 100);
    addComment(db, "B", 1, "comment-b", "bob", 200);
    addMention(db, "B", "comment-b", 1, "alice", "bob", 200);
    addComment(db, "C", 1, "comment-c", "bob", 300);
    addMention(db, "C", "comment-c", 1, "alice", "bob", 300);

    const page = store.listInbox({ userId: "alice" });
    expect(page.items.map((item) => item.sessionId)).toEqual(["B", "A"]);
    expect(page.unreadCount).toBe(2);
    expect(page.items.every((item) => item.kind === "mention")).toBe(true);
  });

  it("derives unread counts from a durable read cursor and never regresses", () => {
    const { db, store } = open();
    seedSession(db, "A");
    addParticipant(db, "A", "alice");
    addParticipant(db, "A", "bob");
    addComment(db, "A", 1, "c1", "bob", 100);
    addMention(db, "A", "c1", 1, "alice", "bob", 100);
    addComment(db, "A", 2, "c2", "bob", 200);
    addMention(db, "A", "c2", 2, "alice", "bob", 200);

    expect(store.unreadCount("alice")).toBe(2);
    store.markRead("alice", "A", 1);
    expect(store.unreadCount("alice")).toBe(1);
    // Cursor is durable across a reopen of the same file would be ideal; here we
    // assert the in-memory row persists and cannot regress.
    expect(() => store.markRead("alice", "A", 0)).not.toThrow();
    expect(store.unreadCount("alice")).toBe(1);
    store.markRead("alice", "A", 2);
    expect(store.unreadCount("alice")).toBe(0);
  });

  it("fails closed on markRead for a non-participant", () => {
    const { db, store } = open();
    seedSession(db, "A");
    addParticipant(db, "A", "alice");
    expect(() => store.markRead("stranger", "A", 5)).toThrow(AttentionInboxError);
  });

  it("does not leak items across a team filter", () => {
    const { db, store } = open();
    seedSession(db, "A", { teamId: "team-1" });
    seedSession(db, "B", { teamId: "team-2" });
    addParticipant(db, "A", "alice");
    addParticipant(db, "A", "bob");
    addParticipant(db, "B", "alice");
    addParticipant(db, "B", "bob");
    addComment(db, "A", 1, "ca", "bob", 100);
    addMention(db, "A", "ca", 1, "alice", "bob", 100);
    addComment(db, "B", 1, "cb", "bob", 200);
    addMention(db, "B", "cb", 1, "alice", "bob", 200);

    const scoped = store.listInbox({ userId: "alice", teamId: "team-1" });
    expect(scoped.items.map((item) => item.sessionId)).toEqual(["A"]);
  });

  it("escalates a lapsed handoff offer to the supervisor exactly once", () => {
    const { db, store } = open();
    seedSession(db, "A");
    addParticipant(db, "A", "alice"); // recipient / responsible
    addParticipant(db, "A", "carol"); // offerer
    addParticipant(db, "A", "sam"); // supervisor
    addResponsibility(db, "A", "carol", "assignee");
    addResponsibility(db, "A", "sam", "supervisor");
    insertEvent(db, "A", 1, "session.handoff.offered", "carol", 100);
    addHandoff(db, "A", 1, "carol", "alice", /* expires */ 500, /* created */ 100);

    const first = store.escalateLapsedHandoffs(1_000);
    expect(first).toHaveLength(1);
    expect(first[0]).toMatchObject({
      supervisorUserId: "sam",
      responsibleUserId: "alice",
      itemKind: "handoff-offer",
      itemSequence: 1,
      sequence: 1,
    });
    // Idempotent: a re-run creates no new escalation.
    expect(store.escalateLapsedHandoffs(1_000)).toHaveLength(0);
    // The handoff now shows as escalated in the supervisor's-adjacent projection.
    const recipientInbox = store.listInbox({ userId: "alice" });
    expect(recipientInbox.items[0]?.escalated).toBe(true);
  });

  it("delivers an unavailable-steerer notification idempotently and fails closed", async () => {
    const { db, store } = open();
    seedSession(db, "A");
    addParticipant(db, "A", "alice");
    addParticipant(db, "A", "carol");
    addResponsibility(db, "A", "carol", "assignee");
    insertEvent(db, "A", 1, "session.handoff.offered", "carol", 100);
    addHandoff(db, "A", 1, "carol", "alice", 500, 100);

    const sent: string[] = [];
    const withBinding: AttentionDeliveryDeps = {
      resolveSessionBinding: () => ({
        bindingId: "binding-1",
        expectedBindingRevision: 1,
        expectedInstallationRevision: 1,
      }),
      deliverOutbound: async (input) => {
        sent.push(input.text);
        return { delivered: true, shouldRetry: false, reason: "delivered" };
      },
    };

    const first = await store.deliverLapsedHandoffNotifications(withBinding, 1_000);
    expect(first).toEqual([
      expect.objectContaining({ userId: "alice", sessionId: "A", outcome: "delivered" }),
    ]);
    expect(sent).toHaveLength(1);

    // Idempotent: a retry after a delivered outcome never re-sends.
    const second = await store.deliverLapsedHandoffNotifications(withBinding, 1_100);
    expect(second[0].outcome).toBe("already-delivered");
    expect(sent).toHaveLength(1);
  });

  it("records no delivery and never sends when no Binding resolves", async () => {
    const { db, store } = open();
    seedSession(db, "A");
    addParticipant(db, "A", "alice");
    addParticipant(db, "A", "carol");
    addResponsibility(db, "A", "carol", "assignee");
    insertEvent(db, "A", 1, "session.handoff.offered", "carol", 100);
    addHandoff(db, "A", 1, "carol", "alice", 500, 100);

    let calls = 0;
    const noBinding: AttentionDeliveryDeps = {
      resolveSessionBinding: () => null,
      deliverOutbound: async () => {
        calls += 1;
        return { delivered: true, shouldRetry: false, reason: "delivered" };
      },
    };
    const results = await store.deliverLapsedHandoffNotifications(noBinding, 1_000);
    expect(results[0].outcome).toBe("no-binding");
    expect(calls).toBe(0);
    expect(database!.db.prepare("SELECT COUNT(*) AS n FROM attention_deliveries").get()).toEqual({
      n: 0,
    });
  });

  it("surfaces an assignee-required ask only to active supervisors", () => {
    const { db, store } = open();
    seedSession(db, "A", { status: "awaiting_assignee" });
    addParticipant(db, "A", "sam"); // supervisor
    addParticipant(db, "A", "pat"); // plain participant
    addResponsibility(db, "A", "sam", "supervisor");
    insertEvent(db, "A", 1, "assignee.required", "sam", 100);

    const supervisorInbox = store.listInbox({ userId: "sam" });
    expect(supervisorInbox.items.map((item) => item.kind)).toEqual(["assignee-required"]);
    expect(supervisorInbox.items[0].sessionId).toBe("A");

    const participantInbox = store.listInbox({ userId: "pat" });
    expect(participantInbox.items).toEqual([]);
  });

  it("paginates deterministically with a stable cursor", () => {
    const { db, store } = open();
    seedSession(db, "A");
    addParticipant(db, "A", "alice");
    addParticipant(db, "A", "bob");
    for (let i = 1; i <= 5; i += 1) {
      addComment(db, "A", i, `c${i}`, "bob", 100 + i);
      addMention(db, "A", `c${i}`, i, "alice", "bob", 100 + i);
    }
    const first = store.listInbox({ userId: "alice", limit: 2 });
    expect(first.items).toHaveLength(2);
    expect(first.nextCursor).not.toBeNull();
    const second = store.listInbox({ userId: "alice", limit: 2, cursor: first.nextCursor });
    expect(second.items).toHaveLength(2);
    const firstIds = first.items.map((i) => i.itemId);
    const secondIds = second.items.map((i) => i.itemId);
    expect(firstIds.some((id) => secondIds.includes(id))).toBe(false);
  });
});
