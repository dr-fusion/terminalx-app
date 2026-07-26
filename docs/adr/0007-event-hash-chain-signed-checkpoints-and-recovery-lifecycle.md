---
status: accepted
---

# Event hash chain, signed checkpoints, external retention, and the recovery lifecycle

## Context

[Phase 4](../multiplayer/phase-4-release-gates.md) enumerated eight release gates.
Phase 10 closes the last two:

- **Gate 8 (Event/evidence integrity):** Session events and evidence must be
  append-only, hash-chained, signed, attributable, and externally retainable,
  with immutable evidence-review history and Goal version lineage.
- **Gate 7 (Emergency recovery):** a pre-Run platform-security quarantine/retire/
  retry path, a version-fenced terminal lifecycle (end, runtime retirement,
  cancellation, archive, retention) that resolves racing operations to one
  terminal state, and durably persisted monotonic Runtime cursors that reject a
  conflicting or regressed replay after restart.

The `session_events` table already allocated a transactional monotonic
per-session `sequence` (`appendEvent`) but carried no hash chain, signature, or
external retention. Phases 6–9 established the disciplines this phase reuses:
Ed25519-signed, domain-separated, digest-only evidence; versioned SQLite
migrations with immutable triggers; generation fences; and monotonic,
crash-safe cursors.

## Decision

### Gate 8 — Event and evidence integrity

**Hash chain.** Every `session_events` row is bound into an append-only hash
chain (`src/lib/team-sessions/session-event-chain.ts`). Each event stores a
`prev_hash` and a canonical `hash` over
`(schema, sessionId, sequence, type, occurredAtMs, actor, source, payload,
prev_hash)`. The chain begins from a single fixed, domain-separated genesis
root — the same constant for every session; the per-event commitment to
`sessionId` already prevents chains from being swapped between sessions, and
using a fixed root lets the SQLite trigger compare against a literal. The hash
is computed over the JSON-round-tripped payload so a live append and the
migration backfill produce identical digests. Every `session_events` writer —
the Team Session kernel's `appendEvent` and the Runtime lifecycle, compensation,
and receipt-follow journals — emits the chain via one shared
`chainedSessionEventHashes` helper.

**Append-only, tamper-evident storage.** New SQLite triggers forbid every
`UPDATE`/`DELETE` on `session_events` and reject any insert whose `prev_hash`
does not match the predecessor's `hash` (or the genesis root at sequence 1), so
tamper, gap, reorder, and deletion are impossible in-band and detectable
out-of-band. `verifySessionEventChain` recomputes the chain and reports the exact
first failure (`hash-mismatch`, `gap`, `reorder`, `prev-hash-mismatch`,
`genesis-mismatch`).

**Attributable.** Every event already carries `actor` (kind + user id + display
name) and `source` (scope + key); both are inside the hashed content, and there
is no unattributed append path — every writer routes through `appendEvent` or the
journal system-event helpers, which always populate actor and source.

**Signed checkpoints.** A checkpoint is an Ed25519 signature over the chain head
`(sessionId, headSequence, headHash, genesisRoot)`, persisted digest+signature-
only and immutable-by-trigger in `session_event_checkpoints`. It is signed with a
**dedicated session-event-checkpoint key** — a distinct trust key managed exactly
like the runtime authority, broker, and approval-provenance keys (private half
loaded once from a `0600` key file under the trust root, never leaving the main
process; public half published; each signature carries a `signingKeyId` so
rotation is a set of trusted keys). Signing and verification fail closed: emitting
a checkpoint without a configured key throws, the store never signs an invalid
head, and a checkpoint that does not verify is reported unverified rather than
trusted. `session.end` emits a checkpoint when a key is configured.

**Externally retainable.** `exportSessionEventChain` produces a stable,
self-verifying bundle (schema, sessionId, genesis root, the ordered event chain,
and the signed checkpoints). `verifyExportedSessionEventChain` re-derives the
chain and authenticates every checkpoint against trusted public keys with no
TerminalX state — the externally-retainable release evidence that Phase 8's
internal ledger explicitly was not. A checkpoint whose head does not match the
re-derived chain, or that is signed by an untrusted key, rejects the bundle.

**Immutable evidence-review history and Goal version lineage.**
`evidence_review_history` records, append-only, who reviewed exactly which
evidence (a digest over the ordered reviewed-evidence digests) at which Goal
version with what disposition; it is keyed so a given `(Goal, version)` review is
recorded once. `goal_version_lineage` records, append-only, each Goal version,
its predecessor version, and the command that produced it. Both are immutable by
trigger.

### Gate 7 — Recovery and terminal lifecycle

**Pre-Run platform-security quarantine/retire/retry.** `session.platform-security.act`
contains, retires, or re-provisions a Runtime Assignment for platform-security
reasons **before any Run has bound it** (previously `safety.quarantine` was a
Runtime capability that presupposed a source lifecycle command and a Run). Each
action is fenced against the observed runtime authorization generation,
idempotent by a single-use key (a replay returns the recorded outcome, a
different action under the same key fails closed), and recorded in the
append-only `session_platform_security_actions` history. Quarantine freezes the
assignment and advances the authorization generation to `quarantined`; retire
terminates it; retry retires the contained assignment and provisions a fresh
`provisioning` replacement under an advanced generation that awaits the normal
enforcement flow (it is never marked `enforced` on the bump itself, honoring the
existing authorization-transition invariant).

**Version-fenced terminal lifecycle.** `session.end` lets a Supervisor end a
Team Session under an exact `access_revision` fence. It requires outstanding
Runtime work to be resolved first (no non-terminal Run, no pending/processing
outbox) so end cannot race a live dispatch to a torn state, retires the current
Runtime Assignment, and makes the session an immutable, still-chain-verifiable
archive (`ended_at_ms`, `archived_at_ms`) with a retention horizon
(`retention_expires_at_ms`). Once ended, every other steering/lifecycle command
fails closed, so racing end/stop/resume/handoff/approval resolve to one
consistent terminal state; a second end is rejected.

**Monotonic Runtime cursors.** Durable, monotonic runtime observation/receipt
cursors already exist from Phase 6: `runtime_receipt_follow_streams` persists a
strictly monotonic `receipt_sequence` plus the signed cursor/observation-digest
chain, enforced by triggers that admit only an exact `+1` advance linked to the
just-inserted event and reject any gap, fork, duplicate, or regressed cursor;
after restart the persisted checkpoint is reloaded and an observation whose
`previous` does not match is contained (quarantined). Phase 10 relies on that
mechanism unchanged; the remaining work — driving it at real hosted-runtime
receipt volume across a real crash/restart — is Phase 12.

## Honest evidence boundary versus Phase 12

No hosted execution is live. The hash chain, checkpoints, export/import, evidence/
Goal lineage, terminal lifecycle, and pre-Run platform-security path are verified
against the real SQLite database and the hermetic harness. Real crash/restart at
hosted-runtime volume — and platform-security actions and cursor replay driven by
a real hosted Daytona Runtime — are Phase 12 deliverables; this phase builds and
verifies the mechanisms against the real modules and the hermetic harness.

## Consequences

- Every Session event is append-only and hash-chained from a fixed genesis root;
  tamper/gap/reorder/deletion is detectable, a signed checkpoint attests the head,
  and an exported bundle self-verifies without TerminalX state or the signing key.
- Evidence review and Goal version history are immutable and attributable.
- A Runtime Assignment can be quarantined/retired/retried for platform-security
  reasons before a Run exists, fenced, idempotent, and audited.
- A Team Session ends under an exact fence into an immutable, verifiable, retained
  archive, and racing terminal operations converge on one state.
- Gates 7 and 8 are mechanism-complete on the real database and hermetic harness;
  their real-hosted-runtime evidence closes in Phase 12.
