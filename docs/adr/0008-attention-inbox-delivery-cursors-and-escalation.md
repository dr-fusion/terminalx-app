---
status: accepted
---

# Global attention inbox, delivery/read cursors, deadline escalation, and chat completion

## Context

[Phase 11](../production-readiness/roadmap.md) completes the externally usable
application around the closed security gates. Its first two bullets are Phase
11A:

- A **global, cross-session attention inbox** for a User, with durable read and
  delivery cursors, deadlines, escalation, and Slack/Telegram notification
  delivery for unavailable steerers.
- **Chat completion:** pagination, server-side search, unread/read state,
  `@mentions`, artifact attachments, and client virtualization for long
  timelines.

Before Phase 11A the inbox was per-session only (`session.inbox` listing). The
attention/steering asks directed at a User — the mentions in the conversation,
the Handoff offers awaiting their acceptance, and the assignee-required asks a
Supervisor must resolve — were not aggregated anywhere the User could see them
across their Sessions, had no durable unread accounting, and lapsed silently
when a deadline passed.

Phases 8–10 established the disciplines this phase reuses: versioned SQLite
migrations with immutable/append-only triggers; per-scope, domain-separated hash
chains as tamper-evident append-only logs; visibility fences that fail closed;
and the existing outbound egress (`deliverOutboundMessage` + the Channel Binding
authority) as the single path any notification leaves the system through.

## Decision

### The attention inbox is a projection over existing durable authority

The inbox does not introduce a new authoritative "attention item" record. It
**aggregates** what the kernel already holds — `comment_mentions` (new Phase 11A
evidence), `session_handoffs` offered to the User, and `awaiting_assignee`
Sessions the User supervises — and projects each as an `AttentionItem` keyed by
its originating Session Event `sequence`. Every source is fenced to a currently
active Participant, so the inbox can never cross a session-visibility boundary,
and it invents no authority the kernel does not already have.

### Durable read and delivery cursors (schema v18)

The additive v18 migration adds:

- `user_attention_reads` — a durable, per-User/per-Session read cursor
  (`read_through_sequence`). Unread counts derive from it; a `BEFORE UPDATE`
  trigger forbids regression. It is a mutable projection, not evidence.
- `attention_escalations` — an append-only, per-Session, **hash-chained**
  escalation log, idempotent by `(session_id, item_kind, item_sequence,
supervisor_user_id)`.
- `attention_deliveries` — an append-only, per-User, **hash-chained** delivery
  log, idempotent by `(user_id, session_id, item_sequence, binding_id)`; the
  per-User `MAX(sequence)` is the delivery cursor.
- `comment_mentions` / `comment_attachments` — append-only comment evidence (see
  chat completion below).

The escalation and delivery chains use their own domain-separated genesis roots
(`attention-chain.ts`), distinct from the Session Event Chain and from each
other, so an entry in one log can never be confused with an entry in another.
Comment bodies themselves remain in the canonical event chain; no chat table
stores a body.

### Deadlines and escalation

`escalateLapsedHandoffs(now)` finds Handoff offers whose deadline has lapsed
while still open and, per the CONTEXT.md steering model, escalates each to every
active **Supervisor** who has not already been escalated for that item, appending
one tamper-evident row per (item, Supervisor). It is idempotent: a re-run never
double-escalates.

### Notification delivery for unavailable steerers

`deliverLapsedHandoffNotifications(deps, now)` delivers a notification for each
lapsed Handoff to the unavailable responsible steerer's bound channel **through
the injected existing outbound egress** — never a second egress path. Delivery is
recorded against the delivery cursor and is idempotent (an outcome already
recorded for the exact User/Session/item/Binding is never re-sent), and it
**fails closed**: when no Binding/authority resolves there is no external
delivery and nothing is recorded, while the in-app inbox still reflects the item.

Escalation and delivery are exposed as authority methods on `AttentionInboxStore`
for an operational maintenance driver to invoke; wiring a periodic tick is a
Phase 11C (operations) concern.

### Chat completion

`comment.add` now parses `@userId` mentions from the body server-side, resolves
them to canonical Users who are active Participants (never crossing the Session
boundary), and records append-only `comment_mentions` that feed the inbox.
Optional artifact attachments are validated and bounded server-side and recorded
as append-only `comment_attachments`; any outbound mirror continues to respect
the Binding `allowArtifacts` policy through the existing egress. Pagination and
stable ordering reuse the existing sequence-ordered `session.events` read;
client virtualization bounds the rendered DOM with a windowing helper on top of
per-item `content-visibility`.

### HTTP

`GET /api/attention` (cursor-paginated inbox), `GET /api/attention/unread-count`,
and `POST /api/attention/read` follow the existing route/authz style: fail-closed
actor authentication, same-origin CSRF fencing for cookie sessions, read-only and
mutation-availability gates, and no cross-session leakage.

## Consequences

- Unread accounting and escalation are durable and survive restart; the delivery
  and escalation logs are externally verifiable append-only chains.
- Because the inbox is a projection, revoking a Participant immediately removes
  their access to a Session's items with no extra bookkeeping.
- Escalation/delivery require an operational driver to invoke them on a schedule;
  until Phase 11C wires that tick, they run only when called explicitly (for
  example from a test or an operator task).
- Server-side full-text search over conversation content is **not** part of this
  slice; pagination and visibility-fenced reads are in place, and search is a
  precise follow-up (see the roadmap).
