---
status: accepted
---

# Approval provenance, authoritative limits, and the YOLO challenge

## Context

[Phase 4](../multiplayer/phase-4-release-gates.md) established the Action Grant,
approval, and Grant Review contracts and the version-fenced `action_grants` /
`action_grant_states` / `grant_reviews` state machine, but deferred three release
gates:

- **Gate 4 (Approval provenance):** approval decisions and signed grants must be
  bound to an immutable actor and capability snapshot; canonical budgets and
  usage-ledger lineage must be part of the approved authority; Grant Review must
  capture exact grant-state versions and either require a fresh approval for a
  reissue or model an explicit review-authorized lineage.
- **Gate 5 (Authoritative limits):** wall clock, model tokens/spend, outbound
  bytes, and action counts must be reserved and accounted from Runtime receipts,
  fail closed at configured caps, and persist circuit-breaker state. Until this
  existed the read model reported `accounting-unavailable`.
- **Gate 6 (YOLO challenge):** YOLO must stay ineligible until a server-issued,
  actor/session/policy/Sandbox-bound, expiring, one-use confirmation and the
  initial Action Grant are atomically consumed.

Phases 6–8 established the disciplines this phase reuses: Ed25519-signed,
domain-separated, digest-only evidence (the Secret Broker registration receipt
and the runtime enforcement proof); versioned SQLite migrations with immutable
triggers; generation fences; and the single-use, rate-limited, digest-only
Link Challenge.

## Decision

### Gate 4 — Approval provenance

At approval time the authority signs an **immutable approval-provenance
snapshot** binding the resolving actor, the exact approved capability
(`digestApprovalCapability` over action class, provider, operation, target, and
scope), the run policy digest, the grant budget digest, the Sandbox identity
(`RuntimeBinding`), the runtime authorization generation, and the grant-state
version at approval time. It is Ed25519-signed with a **dedicated
approval-provenance key** — a distinct trust key managed exactly like the runtime
authority and broker keys (private half loaded once from a `0600` key file under
the trust root, never leaving the main process; public half published for local
verification; each signature carries a `signingKeyId` so rotation is a set of
trusted keys). Verification is fail-closed. Provenance is persisted digest-only
and immutable-by-trigger in `approval_provenance` (`src/lib/runtime/approval-provenance.ts`,
`src/lib/team-sessions/sqlite-approval-provenance-store.ts`).

**Reissue/review lineage** is an append-only `grant_lineage` table: a successor
grant records what it `reissues` or `supersedes` and the exact `grant_reviews`
version that authorized it, immutable by trigger. This complements the existing
Grant Review state machine rather than replacing it.

**Atomic grant usage** is `grant_consumptions`, keyed by `grant_id` (PRIMARY KEY)
so a grant is consumed exactly once. `consumeGrant` inserts the consumption row
and the `action_grant_states` transition to `consumed` in one transaction;
concurrent or duplicate consumption aborts on the primary key, and a crash-retry
with the same consumption receipt digest converges idempotently while a different
effect against a consumed grant fails closed.

**Boundary-change revocation** is `invalidateOutstandingGrants`: when the Runtime
Assignment / Sandbox identity changes, every non-terminal grant for the Run is
transitioned to `invalidated` with the boundary reason, so outstanding grants stop
resolving and a re-approval is required. This uses the existing generation-fenced
`action_grant_states` transitions and reasons.

### Gate 5 — Authoritative limits

Canonical units are explicit integers with explicit rounding
(`src/lib/runtime/authoritative-limits.ts`): wall time in whole milliseconds,
model tokens as integers, model spend in whole currency minor units tagged by an
ISO-4217 code, outbound bytes as integers, and action counts per `ActionClass`.
Rounding is an explicit mode (`ceil` for conservative consumption, `floor` for
headroom, `exact` rejects fractional input). Every accumulation is checked for
overflow and every subtraction for underflow, failing closed. **An unset limit is
UNLIMITED and that is the explicit default:** a `RunLimit` is the closed union of
`unconfigured` and `capped`; `null`/`0`/`Infinity` are never sentinels, and a
missing row is never silently treated as unlimited or zero.

The durable ledger (`limit_reservations` + `limit_settlements`,
`src/lib/team-sessions/sqlite-limit-ledger-store.ts`) is keyed to Runtime-receipt
identity: `reserve` is idempotent by the reserve receipt digest, `settle`/`release`
by the settle receipt digest. `reserve` admits an effect only when projected
committed usage (settled actuals plus still-open reservations) stays within the
canonical limits; a crash between reserve and settle leaves a conservative
reserved row that still counts until settled or released. Duplicate receipts never
double-count. Enforcement is **fail-closed**: the read model now derives its
status band from the ledger and only reports `accounting-unavailable` if the
ledger cannot be read, so compliance is never asserted without authoritative
accounting.

Circuit-breaker state is persisted durably (`circuit_breaker_state` plus
`RuntimeCircuitBreaker.snapshotScope`/`loadScope`) so an open circuit or a
denied-proposal set survives a restart. This is the one operational (upsertable)
Phase 9 projection; every other new table is immutable evidence or an idempotent
ledger.

### Gate 6 — YOLO challenge

A YOLO challenge (`src/lib/runtime/yolo-challenge.ts`,
`src/lib/team-sessions/sqlite-yolo-challenge-store.ts`) is server-issued,
expiring, single-use, and bound to the exact actor, session, run policy digest,
and Sandbox identity via a domain-separated binding digest. Issuance is
rate-limited per actor/session (window and active-count caps mirroring the Link
Challenge), and only the token digest is persisted. The challenge is consumed
**atomically with the initial Action Grant**: the `mint` callback that creates the
first autonomous grant runs inside the same transaction that flips the single-use
row to `consumed`, so a crash or a duplicate submission can never mint two grants
from one proof. A changed Sandbox/boundary invalidates outstanding challenges
(`invalidateForBoundaryChange`), tying Gate 6 to Gate 4 revocation.

Per the roadmap this authority stays **"Open and unexposed"**: the authority,
lifecycle, atomic consumption, and boundary invalidation are implemented and
tested, but **no browser route lets a user obtain a YOLO challenge in the running
app** — that is a Phase 11 product decision. The executor already knows `yolo`
mode and `initialYoloActionGrantId`; the challenge is the missing server-issued
proof that gates minting that first autonomous grant.

## Honest evidence boundary versus Phase 12

No hosted execution is live yet. The authoritative limit ledger is wired to the
receipt sources that exist today (the 8D proxy accounting and the command
receipts) and to the hermetic hosted harness. Real-runtime receipt volume —
reservations driven by a real hosted Daytona Runtime — is a Phase 12 deliverable;
this phase builds and verifies the mechanisms against the real modules and the
hermetic harness.

## Consequences

- Every approval carries a signed, immutable, digest-only provenance record and,
  where applicable, an append-only lineage to the review that authorized its
  reissue; a grant can be consumed exactly once even under concurrency, duplicate
  delivery, or crash-retry; and a boundary change fences off all outstanding
  grants.
- Limits are reserved and accounted in canonical integer units from receipt
  identity, unlimited is an explicit audited default, the circuit breaker
  survives restart, and the read model reports real utilisation, failing closed to
  `accounting-unavailable`.
- YOLO cannot be entered without a server-issued, boundary-bound, single-use
  challenge consumed atomically with the initial grant, and it remains unexposed
  at the product surface until Phase 11.
- Gates 4, 5, and 6 are mechanism-complete on the existing receipt/harness
  sources; their real-hosted-runtime evidence closes in Phase 12.
