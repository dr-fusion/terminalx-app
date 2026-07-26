import { randomUUID } from "node:crypto";
import type Database from "better-sqlite3";
import {
  chainedDeliveryHashes,
  chainedEscalationHashes,
  type DeliveryChainContent,
  type EscalationChainContent,
} from "./attention-chain";
import {
  DEFAULT_ATTENTION_PAGE,
  MAX_ATTENTION_PAGE,
  MAX_ATTENTION_SCAN,
  type AttentionDeliveryDeps,
  type AttentionDeliveryResult,
  type AttentionEscalation,
  type AttentionInboxPage,
  type AttentionInboxQuery,
  type AttentionItem,
  type AttentionItemKind,
} from "./contracts";

export class AttentionInboxError extends Error {
  constructor(
    readonly code: "not-authorized" | "invalid",
    message: string
  ) {
    super(message);
    this.name = "AttentionInboxError";
  }
}

type Row = Record<string, unknown>;

interface Cursor {
  readonly c: number;
  readonly s: string;
  readonly k: string;
  readonly q: number;
}

const KIND_RANK: Record<AttentionItemKind, number> = {
  "handoff-offer": 0,
  "assignee-required": 1,
  mention: 2,
};

/**
 * The durable authority for the cross-session attention inbox, delivery/read
 * cursors, deadline escalation, and notification delivery. It reads existing
 * durable kernel state (Participants, Handoffs, session status, and the Phase
 * 11A `comment_mentions` evidence) so it never invents an authority the kernel
 * does not already hold, and it fails closed on every visibility fence.
 */
export class AttentionInboxStore {
  private readonly db: Database.Database;
  private readonly clock: () => number;
  private readonly newId: () => string;

  constructor(
    db: Database.Database,
    options: { clock?: () => number; idGenerator?: () => string } = {}
  ) {
    this.db = db;
    this.clock = options.clock ?? (() => Date.now());
    this.newId = options.idGenerator ?? (() => randomUUID());
  }

  // --- Read side -----------------------------------------------------------

  listInbox(query: AttentionInboxQuery): AttentionInboxPage {
    const userId = requireUserId(query.userId);
    const limit = clampLimit(query.limit);
    const cursor = decodeCursor(query.cursor ?? null);
    return this.db.transaction((): AttentionInboxPage => {
      const all = this.aggregate(userId, query.teamId);
      const unreadCount = all.reduce((count, item) => count + (item.read ? 0 : 1), 0);
      const filtered = query.unreadOnly ? all.filter((item) => !item.read) : all;
      const sorted = filtered.sort(compareItems);
      const start = cursor ? sorted.findIndex((item) => isAfterCursor(item, cursor)) : 0;
      const from = start < 0 ? sorted.length : start;
      const page = sorted.slice(from, from + limit);
      const last = page.at(-1);
      const hasMore = last !== undefined && from + limit < sorted.length;
      return {
        items: page,
        unreadCount,
        nextCursor: hasMore && last ? encodeCursor(last) : null,
      };
    })();
  }

  unreadCount(userId: string, teamId?: string): number {
    const normalized = requireUserId(userId);
    return this.db.transaction((): number => {
      const all = this.aggregate(normalized, teamId);
      return all.reduce((count, item) => count + (item.read ? 0 : 1), 0);
    })();
  }

  /**
   * Advance the durable read cursor for one Session to `throughSequence`. Fails
   * closed unless the caller is a currently active Participant of the Session.
   * The cursor never regresses (the SQLite trigger enforces it too).
   */
  markRead(
    userId: string,
    sessionId: string,
    throughSequence: number
  ): { readThroughSequence: number } {
    const normalized = requireUserId(userId);
    const session = requireIdentifier(sessionId, "Session id");
    if (!Number.isSafeInteger(throughSequence) || throughSequence < 0) {
      throw new AttentionInboxError("invalid", "Read cursor sequence is invalid");
    }
    return this.db.transaction((): { readThroughSequence: number } => {
      if (!this.isActiveParticipant(session, normalized)) {
        throw new AttentionInboxError("not-authorized", "Not a Participant of this Session");
      }
      const now = this.clock();
      this.db
        .prepare(
          `INSERT INTO user_attention_reads
             (user_id, session_id, read_through_sequence, updated_at_ms)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(user_id, session_id) DO UPDATE SET
             read_through_sequence = excluded.read_through_sequence,
             updated_at_ms = excluded.updated_at_ms
           WHERE excluded.read_through_sequence > user_attention_reads.read_through_sequence`
        )
        .run(normalized, session, throughSequence, now);
      const row = this.db
        .prepare(
          `SELECT read_through_sequence FROM user_attention_reads
           WHERE user_id = ? AND session_id = ?`
        )
        .get(normalized, session) as Row | undefined;
      return { readThroughSequence: (row?.read_through_sequence as number) ?? 0 };
    })();
  }

  // --- Escalation ----------------------------------------------------------

  /**
   * Escalate every Handoff offer whose deadline has lapsed while still open to
   * each active Supervisor who has not already been escalated for that item.
   * Idempotent: a re-run never double-escalates. Each escalation is appended to
   * the per-Session, tamper-evident escalation chain.
   */
  escalateLapsedHandoffs(now: number = this.clock()): AttentionEscalation[] {
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new AttentionInboxError("invalid", "Escalation time is invalid");
    }
    return this.db.transaction((): AttentionEscalation[] => {
      const lapsed = this.db
        .prepare(
          `SELECT session_id, context_sequence, recipient_user_id, expires_at_ms
             FROM session_handoffs
            WHERE status = 'offered' AND expires_at_ms <= ?
            ORDER BY session_id ASC, context_sequence ASC`
        )
        .all(now) as Row[];
      const created: AttentionEscalation[] = [];
      for (const handoff of lapsed) {
        const sessionId = handoff.session_id as string;
        const itemSequence = handoff.context_sequence as number;
        const responsibleUserId = handoff.recipient_user_id as string;
        const deadlineAtMs = handoff.expires_at_ms as number;
        const supervisors = this.db
          .prepare(
            `SELECT user_id FROM session_responsibilities
              WHERE session_id = ? AND kind = 'supervisor' AND status = 'active'
              ORDER BY user_id ASC`
          )
          .all(sessionId) as Row[];
        for (const supervisor of supervisors) {
          const supervisorUserId = supervisor.user_id as string;
          if (supervisorUserId === responsibleUserId) continue;
          const existing = this.db
            .prepare(
              `SELECT 1 FROM attention_escalations
                WHERE session_id = ? AND item_kind = 'handoff-offer'
                  AND item_sequence = ? AND supervisor_user_id = ?`
            )
            .get(sessionId, itemSequence, supervisorUserId);
          if (existing) continue;
          created.push(
            this.appendEscalation({
              sessionId,
              itemKind: "handoff-offer",
              itemSequence,
              responsibleUserId,
              supervisorUserId,
              deadlineAtMs,
              escalatedAtMs: now,
            })
          );
        }
      }
      return created;
    })();
  }

  private appendEscalation(
    input: Omit<AttentionEscalation, "id" | "sequence">
  ): AttentionEscalation {
    const head = this.db
      .prepare(
        `SELECT sequence, hash FROM attention_escalations
          WHERE session_id = ? ORDER BY sequence DESC LIMIT 1`
      )
      .get(input.sessionId) as Row | undefined;
    const sequence = ((head?.sequence as number) ?? 0) + 1;
    const content: EscalationChainContent = {
      sessionId: input.sessionId,
      sequence,
      itemKind: input.itemKind,
      itemSequence: input.itemSequence,
      responsibleUserId: input.responsibleUserId,
      supervisorUserId: input.supervisorUserId,
      deadlineAtMs: input.deadlineAtMs,
      escalatedAtMs: input.escalatedAtMs,
    };
    const { prevHash, hash } = chainedEscalationHashes((head?.hash as string) ?? null, content);
    const id = this.newId();
    this.db
      .prepare(
        `INSERT INTO attention_escalations
           (id, session_id, sequence, item_kind, item_sequence,
            responsible_user_id, supervisor_user_id, deadline_at_ms, escalated_at_ms,
            prev_hash, hash, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        input.sessionId,
        sequence,
        input.itemKind,
        input.itemSequence,
        input.responsibleUserId,
        input.supervisorUserId,
        input.deadlineAtMs,
        input.escalatedAtMs,
        prevHash,
        hash,
        input.escalatedAtMs
      );
    return { id, sequence, ...input };
  }

  // --- Delivery ------------------------------------------------------------

  /**
   * Deliver a notification for each lapsed-deadline Handoff to the unavailable
   * responsible steerer's bound Slack/Telegram channel, through the injected
   * (existing) outbound egress. Idempotent: a delivery already recorded for the
   * exact (User, Session, item, Binding) is never re-sent. Fails closed with
   * `no-binding` when no Binding/authority resolves — the in-app inbox still
   * reflects the item regardless.
   */
  async deliverLapsedHandoffNotifications(
    deps: AttentionDeliveryDeps,
    now: number = this.clock()
  ): Promise<AttentionDeliveryResult[]> {
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new AttentionInboxError("invalid", "Delivery time is invalid");
    }
    const lapsed = this.db
      .prepare(
        `SELECT session_id, context_sequence, recipient_user_id
           FROM session_handoffs
          WHERE status = 'offered' AND expires_at_ms <= ?
          ORDER BY session_id ASC, context_sequence ASC`
      )
      .all(now) as Row[];
    const results: AttentionDeliveryResult[] = [];
    for (const handoff of lapsed) {
      const sessionId = handoff.session_id as string;
      const itemSequence = handoff.context_sequence as number;
      const userId = handoff.recipient_user_id as string;
      results.push(
        await this.deliverOne(deps, {
          userId,
          sessionId,
          itemKind: "handoff-offer",
          itemSequence,
          text: `Handoff awaiting your response is past its deadline in ${sessionId}`,
          now,
        })
      );
    }
    return results;
  }

  private async deliverOne(
    deps: AttentionDeliveryDeps,
    input: {
      userId: string;
      sessionId: string;
      itemKind: AttentionDeliveryResult["itemKind"];
      itemSequence: number;
      text: string;
      now: number;
    }
  ): Promise<AttentionDeliveryResult> {
    const base = {
      userId: input.userId,
      sessionId: input.sessionId,
      itemKind: input.itemKind,
      itemSequence: input.itemSequence,
    };
    const binding = deps.resolveSessionBinding(input.sessionId);
    if (!binding) {
      // Fail closed: no Binding/authority means no external delivery. The
      // in-app inbox and escalation log are unaffected.
      return { ...base, outcome: "no-binding" };
    }
    const alreadyDelivered = this.db
      .prepare(
        `SELECT 1 FROM attention_deliveries
          WHERE user_id = ? AND session_id = ? AND item_sequence = ? AND binding_id = ?`
      )
      .get(input.userId, input.sessionId, input.itemSequence, binding.bindingId);
    if (alreadyDelivered) {
      return { ...base, outcome: "already-delivered" };
    }
    const decision = await deps.deliverOutbound({
      bindingId: binding.bindingId,
      expectedBindingRevision: binding.expectedBindingRevision,
      expectedInstallationRevision: binding.expectedInstallationRevision,
      messageKind: "mention",
      includesArtifacts: false,
      text: input.text,
      attempt: 0,
    });
    if (decision.shouldRetry) {
      // Transient failure: record nothing so a later maintenance tick retries.
      return { ...base, outcome: "retry-scheduled" };
    }
    const outcome = decision.delivered
      ? "delivered"
      : decision.reason === "denied"
        ? "denied"
        : decision.reason === "retries-exhausted"
          ? "retries-exhausted"
          : "not-routed";
    // Record the terminal outcome so a retry/restart never re-sends this item.
    this.recordDelivery({
      userId: input.userId,
      sessionId: input.sessionId,
      itemKind: input.itemKind,
      itemSequence: input.itemSequence,
      bindingId: binding.bindingId,
      outcome,
      now: input.now,
    });
    return { ...base, outcome };
  }

  private recordDelivery(input: {
    userId: string;
    sessionId: string;
    itemKind: string;
    itemSequence: number;
    bindingId: string;
    outcome: "delivered" | "not-routed" | "denied" | "retries-exhausted";
    now: number;
  }): void {
    const head = this.db
      .prepare(
        `SELECT sequence, hash FROM attention_deliveries
          WHERE user_id = ? ORDER BY sequence DESC LIMIT 1`
      )
      .get(input.userId) as Row | undefined;
    const sequence = ((head?.sequence as number) ?? 0) + 1;
    const content: DeliveryChainContent = {
      userId: input.userId,
      sequence,
      sessionId: input.sessionId,
      itemKind: input.itemKind,
      itemSequence: input.itemSequence,
      bindingId: input.bindingId,
      outcome: input.outcome,
    };
    const { prevHash, hash } = chainedDeliveryHashes((head?.hash as string) ?? null, content);
    this.db
      .prepare(
        `INSERT INTO attention_deliveries
           (id, user_id, sequence, session_id, item_kind, item_sequence,
            binding_id, outcome, prev_hash, hash, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        this.newId(),
        input.userId,
        sequence,
        input.sessionId,
        input.itemKind,
        input.itemSequence,
        input.bindingId,
        input.outcome,
        prevHash,
        hash,
        input.now
      );
  }

  // --- Aggregation ---------------------------------------------------------

  private aggregate(userId: string, teamId?: string): AttentionItem[] {
    const items: AttentionItem[] = [];
    items.push(...this.mentionItems(userId, teamId));
    items.push(...this.handoffItems(userId, teamId));
    items.push(...this.assigneeRequiredItems(userId, teamId));
    return items.slice(0, MAX_ATTENTION_SCAN);
  }

  private mentionItems(userId: string, teamId?: string): AttentionItem[] {
    const rows = this.db
      .prepare(
        `SELECT m.session_id AS session_id, m.comment_sequence AS item_sequence,
                m.author_user_id AS author_user_id, m.created_at_ms AS created_at_ms,
                s.team_id AS team_id, s.project_id AS project_id, s.name AS name,
                s.status AS status,
                COALESCE(r.read_through_sequence, 0) AS read_through
           FROM comment_mentions m
           JOIN sessions s ON s.id = m.session_id
           JOIN session_participants p
             ON p.session_id = m.session_id AND p.user_id = m.mentioned_user_id
            AND p.status = 'active'
           LEFT JOIN user_attention_reads r
             ON r.user_id = m.mentioned_user_id AND r.session_id = m.session_id
          WHERE m.mentioned_user_id = ?
            ${teamId ? "AND s.team_id = ?" : ""}
          ORDER BY m.created_at_ms DESC
          LIMIT ${MAX_ATTENTION_SCAN}`
      )
      .all(...(teamId ? [userId, teamId] : [userId])) as Row[];
    return rows.map((row) => this.projectItem(row, "mention", null));
  }

  private handoffItems(userId: string, teamId?: string): AttentionItem[] {
    const rows = this.db
      .prepare(
        `SELECT h.session_id AS session_id, h.context_sequence AS item_sequence,
                h.offerer_user_id AS author_user_id, h.created_at_ms AS created_at_ms,
                h.expires_at_ms AS deadline_at_ms,
                s.team_id AS team_id, s.project_id AS project_id, s.name AS name,
                s.status AS status,
                COALESCE(r.read_through_sequence, 0) AS read_through,
                EXISTS (
                  SELECT 1 FROM attention_escalations e
                   WHERE e.session_id = h.session_id AND e.item_kind = 'handoff-offer'
                     AND e.item_sequence = h.context_sequence
                ) AS escalated
           FROM session_handoffs h
           JOIN sessions s ON s.id = h.session_id
           JOIN session_participants p
             ON p.session_id = h.session_id AND p.user_id = h.recipient_user_id
            AND p.status = 'active'
           LEFT JOIN user_attention_reads r
             ON r.user_id = h.recipient_user_id AND r.session_id = h.session_id
          WHERE h.recipient_user_id = ? AND h.status = 'offered'
            ${teamId ? "AND s.team_id = ?" : ""}
          ORDER BY h.created_at_ms DESC
          LIMIT ${MAX_ATTENTION_SCAN}`
      )
      .all(...(teamId ? [userId, teamId] : [userId])) as Row[];
    return rows.map((row) => this.projectItem(row, "handoff-offer", row.deadline_at_ms as number));
  }

  private assigneeRequiredItems(userId: string, teamId?: string): AttentionItem[] {
    const rows = this.db
      .prepare(
        `SELECT s.id AS session_id, s.team_id AS team_id, s.project_id AS project_id,
                s.name AS name, s.status AS status, s.created_at_ms AS created_at_ms,
                COALESCE(r.read_through_sequence, 0) AS read_through,
                (
                  SELECT MAX(ev.sequence) FROM session_events ev
                   WHERE ev.session_id = s.id AND ev.type = 'assignee.required'
                ) AS item_sequence
           FROM sessions s
           JOIN session_responsibilities sr
             ON sr.session_id = s.id AND sr.user_id = ?
            AND sr.kind = 'supervisor' AND sr.status = 'active'
           JOIN session_participants p
             ON p.session_id = s.id AND p.user_id = ? AND p.status = 'active'
           LEFT JOIN user_attention_reads r
             ON r.user_id = ? AND r.session_id = s.id
          WHERE s.status = 'awaiting_assignee'
            ${teamId ? "AND s.team_id = ?" : ""}
          ORDER BY s.created_at_ms DESC
          LIMIT ${MAX_ATTENTION_SCAN}`
      )
      .all(...(teamId ? [userId, userId, userId, teamId] : [userId, userId, userId])) as Row[];
    return rows
      .filter((row) => typeof row.item_sequence === "number" && (row.item_sequence as number) >= 1)
      .map((row) => this.projectItem(row, "assignee-required", null));
  }

  private projectItem(
    row: Row,
    kind: AttentionItemKind,
    deadlineAtMs: number | null
  ): AttentionItem {
    const sessionId = row.session_id as string;
    const itemSequence = row.item_sequence as number;
    const readThrough = (row.read_through as number) ?? 0;
    return {
      itemId: `${kind}:${sessionId}:${itemSequence}`,
      kind,
      sessionId,
      teamId: row.team_id as string,
      projectId: row.project_id as string,
      sessionName: row.name as string,
      sessionStatus: row.status as AttentionItem["sessionStatus"],
      itemSequence,
      createdAtMs: row.created_at_ms as number,
      deadlineAtMs,
      read: itemSequence <= readThrough,
      escalated: row.escalated === 1 || row.escalated === true,
      actorUserId: (row.author_user_id as string | undefined) ?? null,
      summary: summarize(kind, row),
    };
  }

  private isActiveParticipant(sessionId: string, userId: string): boolean {
    const row = this.db
      .prepare(
        `SELECT 1 FROM session_participants
          WHERE session_id = ? AND user_id = ? AND status = 'active'`
      )
      .get(sessionId, userId);
    return row !== undefined;
  }
}

function summarize(kind: AttentionItemKind, row: Row): string {
  const name = (row.name as string) ?? "a Team Session";
  switch (kind) {
    case "mention":
      return `You were mentioned in ${name}`;
    case "handoff-offer":
      return `A Handoff in ${name} is awaiting your response`;
    case "assignee-required":
      return `${name} needs an Assignee`;
  }
}

function compareItems(left: AttentionItem, right: AttentionItem): number {
  if (left.createdAtMs !== right.createdAtMs) return right.createdAtMs - left.createdAtMs;
  if (left.sessionId !== right.sessionId) return left.sessionId < right.sessionId ? -1 : 1;
  if (left.kind !== right.kind) return KIND_RANK[left.kind] - KIND_RANK[right.kind];
  return right.itemSequence - left.itemSequence;
}

function isAfterCursor(item: AttentionItem, cursor: Cursor): boolean {
  if (item.createdAtMs !== cursor.c) return item.createdAtMs < cursor.c;
  if (item.sessionId !== cursor.s) return item.sessionId > cursor.s;
  if (item.kind !== cursor.k) {
    return KIND_RANK[item.kind] > (KIND_RANK[cursor.k as AttentionItemKind] ?? 0);
  }
  return item.itemSequence < cursor.q;
}

function encodeCursor(item: AttentionItem): string {
  const cursor: Cursor = {
    c: item.createdAtMs,
    s: item.sessionId,
    k: item.kind,
    q: item.itemSequence,
  };
  return Buffer.from(JSON.stringify(cursor), "utf8").toString("base64url");
}

function decodeCursor(value: string | null): Cursor | null {
  if (value === null || value === "") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
  } catch {
    throw new AttentionInboxError("invalid", "Inbox cursor is invalid");
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof (parsed as Cursor).c !== "number" ||
    typeof (parsed as Cursor).s !== "string" ||
    typeof (parsed as Cursor).k !== "string" ||
    typeof (parsed as Cursor).q !== "number"
  ) {
    throw new AttentionInboxError("invalid", "Inbox cursor is invalid");
  }
  return parsed as Cursor;
}

function clampLimit(limit: number | undefined): number {
  if (limit === undefined) return DEFAULT_ATTENTION_PAGE;
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new AttentionInboxError("invalid", "Inbox limit is invalid");
  }
  return Math.min(limit, MAX_ATTENTION_PAGE);
}

function requireUserId(userId: string): string {
  if (typeof userId !== "string" || userId.length < 1 || userId.length > 300) {
    throw new AttentionInboxError("invalid", "User id is invalid");
  }
  return userId;
}

function requireIdentifier(value: string, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 300) {
    throw new AttentionInboxError("invalid", `${label} is invalid`);
  }
  return value;
}
