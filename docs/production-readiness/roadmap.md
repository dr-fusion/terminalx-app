# TerminalX multiplayer production roadmap

This roadmap is the authoritative phase plan for the production application. There are **13
implementation phases, numbered 0 through 12**. The eight security release gates remain separate
acceptance criteria: a phase may advance more than one gate, and a gate may span more than one
phase.

## Completed foundation

| Phase | Outcome                                                                 | Status   |
| ----- | ----------------------------------------------------------------------- | -------- |
| 0     | Permission-safe baseline and canonical Team Session kernel              | Complete |
| 1     | Canonical Runtime transports and LocalTmux development adapter          | Complete |
| 2     | Durable collaborative conversation                                      | Complete |
| 3     | Orca/Paseo-style multiplayer workspace                                  | Complete |
| 4     | Portable Agent Run, policy, Goal, recovery, and projection contracts    | Complete |
| 5     | Runtime command/receipt executor and durable Gate 1a journal foundation | Complete |
| 6     | Portable end-to-end Runtime-truth kernel                                | Complete |

The completed phases are not an external-pilot release. LocalTmux is a trusted development
adapter, and Agent Run mutations remain closed to HTTP/browser clients.

### Phase 6 — End-to-end Runtime truth

Complete the portable Runtime-truth kernel required by release Gate 1.

Status: complete. The implementation and deliberately closed production boundary are tracked in
[Phase 6 Runtime lifecycle implementation status](../multiplayer/phase-6-runtime-lifecycle.md).

- Add a durable `starting` Run identity and receipt-backed `run.start` lifecycle.
- Make the v4/v5 command journal the only ordinary path for start/pause/resume/stop effects.
- Add command, assignment, follow, and compensation workers with crash-safe leases.
- Bind outbox settlement and supersession to immutable accepted-command evidence and exact source
  events; reject poisoned legacy rows transactionally during schema migration.
- Reconstruct terminal/process write fences from SQLite after restart.
- Fence LocalTmux operations with an immutable `$id` plus a random per-session incarnation across
  resolver, WebSocket, PTY, and teardown boundaries.
- Treat provider timeouts as ambiguous outcomes and reconcile the same command identity.
- Expose Run controls only after exact enforced-receipt tests pass.

## Remaining production phases

### Phase 7 — Daytona hosted isolation

Close the hosted evidence boundary of release Gate 1 and release Gate 2.

- Create and verify the public TerminalX Daytona fork from the reviewed base declared in the
  canonical [`daytona-production-source.json`](../../config/daytona-production-source.json).
- Pin the fork commit and signed SDK, supervisor, runtime-manifest, runner, and daemon artifacts
  with SBOM and provenance; derive runtime identity from measured clean binaries rather than
  operator configuration.
- Compose the hosted adapter, complete signed trust group, and `RuntimeSupervisorRoot` into the
  production server; keep hosted transports unavailable until root readiness, and stop the root
  before closing the Team Session kernel.
- Implement hosted ensure/follow/pause/resume/stop/retire and timeout reconciliation.
- Keep Daytona Sandbox identifiers adapter-private behind opaque TerminalX handles.
- Enforce isolated filesystem, process namespace, identity, network, and resource ceilings.
- Prove stale ensure/retire effects cannot resurrect or delete replacement Sandboxes.

### Phase 8 — Brokered secrets and user connections

Close release Gate 3 and complete the Slack/Telegram/credential connection model.

Status: in progress. Slices 8A–8G are landed: the canonical authentication identity foundation, the
Slice 8B connection authority, the Slice 8C Secret Broker, the Slice 8D Credential Proxy, the Slice
8E Telegram/Slack provider adapters and end-to-end flow, and the Slice 8F/8G hosted enforcement
machinery — Runtime-Assignment-scoped credential eligibility, measured capability activation, and
the adversarial canary evidence suite.

Gate 3: **mechanism + hermetic evidence complete; real-runtime evidence pending Phase 12.** Every
enforcement mechanism and its verification run against the hermetic hosted-runtime harness and the
real broker/proxy modules. Capability activation is per-deployment **measured evidence**, never a
config assertion: nothing in the codebase or configuration statically flips `brokeredCredentials`
or `proxyOnlyEgress` to `true`, and both remain `false` until a valid signed measurement matches the
exact Runtime Assignment. Gate 3 CLOSES only when Phase 12's real hosted Daytona Runtime produces
the same measured evidence through this exact machinery and reruns the canary suite unchanged. The
exact scope and remaining closed boundaries are tracked in
[Phase 8 brokered secrets and connections](../multiplayer/phase-8-brokered-connections.md) and
[ADR 0005](../adr/0005-assignment-scoped-credential-policy-and-measured-capability-activation.md).

The completed Slice 8B hardening binds pairing and Link Challenges to the exact source-JWT expiry, rejects
source-less legacy pairing upgrades, revalidates after local verifier boundaries, and makes logout
revocation depend on durable digest-only tombstones. Pairing codes are digest-only, single-use
SQLite rows with active and rolling issuance limits; paired-device registration and irreversible
revocation use the same transactional database as canonical Users, so concurrent workers cannot
lose a device or revive paired authority. These authentication safeguards do not constitute a
Secret Broker, provider adapter, or closure of Gate 3.

- Store only opaque credential handles in TerminalX state.
- Add approved secret-manager adapters and a destination-scoped credential proxy.
- Make raw tokens, private keys, and secret values unavailable to agents, shells, events, logs,
  evidence, and model output even when explicitly requested.
- Add user-scoped revocable Slack and Telegram connections with least-privilege OAuth scopes,
  tenant/channel/session bindings, provenance, rotation, and webhook replay protection.
- Run seeded-canary exfiltration tests across files, environment, `/proc`, terminal output,
  encoding, artifacts, and outbound requests.

### Phase 9 — Approval provenance, authoritative limits, and YOLO

Advance release Gates 4, 5, and 6.

Status: **mechanism + hermetic evidence complete; real-runtime receipt volume pending Phase 12.**
The mechanisms and their verification run against the real modules and the hermetic hosted-runtime
harness and the receipt sources that exist today (the 8D proxy accounting and command receipts).
The scope and key management are recorded in
[ADR 0006](../adr/0006-approval-provenance-authoritative-limits-and-yolo-challenge.md).

- Sign immutable actor, capability, policy, budget, Sandbox, and state snapshots — done:
  Ed25519 approval-provenance snapshots under a dedicated approval key, persisted digest-only and
  immutable (`approval_provenance`).
- Model explicit reissue/review lineage and atomic grant usage — done: append-only `grant_lineage`
  to the authorizing Grant Review version, and exactly-once `grant_consumptions` consumed
  transactionally with the `consumed` grant-state transition.
- Reserve and account wall time, tokens/spend, outbound bytes, and action counts from Runtime
  receipts; fail closed when accounting is unavailable — done: the durable
  `limit_reservations`/`limit_settlements` ledger, idempotent by receipt identity, replaces the
  `accounting-unavailable` read model with real enforcement that fails closed.
- Persist circuit-breaker state and optional limits, with unlimited as the explicit default — done:
  durable `circuit_breaker_state` with snapshot/restore, and canonical `RunLimit` unlimited-default
  semantics.
- Implement a server-issued, expiring, one-use, actor/session/policy/Sandbox-bound YOLO challenge
  consumed atomically with the initial Action Grant — done, and kept **unexposed** (no browser
  route) per Gate 6's "Open and unexposed" state; product exposure is a Phase 11 decision.
- Support revoking all approvals for a changed Sandbox or changed execution boundary — done:
  generation-fenced invalidation of all outstanding grants and outstanding YOLO challenges.

Gates 4/5/6 CLOSE when Phase 12's real hosted Daytona Runtime drives reservations, provenance, and
YOLO consumption through this exact machinery at real receipt volume.

### Phase 10 — Recovery, evidence, and lifecycle completion

Close release Gates 7 and 8.

Status: **mechanism + hermetic evidence complete; real crash/restart at
hosted-runtime volume pending Phase 12.** The mechanisms and their verification
run against the real modules and the real SQLite database. The scope and key
management are recorded in
[ADR 0007](../adr/0007-event-hash-chain-signed-checkpoints-and-recovery-lifecycle.md).

- Make Session events append-only, hash-chained, signed, attributable, and
  externally retainable — done: the `session_events` hash chain (v17, fixed
  domain-separated genesis, deterministic migration backfill, append-only +
  chain-insert triggers), Ed25519-signed `session_event_checkpoints`, and the
  self-verifying `exportSessionEventChain`/`verifyExportedSessionEventChain`
  bundle.
- Add immutable evidence-review history and Goal version lineage — done:
  append-only `evidence_review_history` and `goal_version_lineage`,
  trigger-enforced.
- Add platform-security quarantine/retire/retry before a Run exists — done:
  `session.platform-security.act`, generation-fenced, idempotent by single-use
  key, and recorded in the append-only `session_platform_security_actions`.
- Add version-fenced `session.end`, runtime retirement, cancellation, archive,
  and retention — done: `session.end` retires the assignment and archives the
  session with a retention horizon under an exact access-revision fence; racing
  end/stop/resume/handoff resolve to one terminal state.
- Persist monotonic Runtime cursors and reject conflicting replay — the durable
  `runtime_receipt_follow_streams` cursor chain (monotonic `receipt_sequence` +
  signed observation chain, no gap/fork/duplicate/regression) landed in Phase 6
  and is reused unchanged.

Gates 7/8 CLOSE when Phase 12's real hosted Daytona Runtime drives the terminal
lifecycle, platform-security actions, and cursor replay through this exact
machinery across a real crash/restart at real receipt volume.

### Phase 11 — Production product and operations

Complete the externally usable application around the closed gates. Phase 11 is
delivered in three sub-slices: 11A (product messaging), 11B (mobile/a11y/
handoff), 11C (operations/deploy).

Status: **11A, 11B, and 11C landed; Phase 11 complete.** The attention inbox
authority, durable cursors, escalation, delivery, and chat completion are
recorded in
[ADR 0008](../adr/0008-attention-inbox-delivery-cursors-and-escalation.md). 11B
added mobile navigation, an accessibility pass, structured handoff
artifacts/blockers, operator error states, and the carried server-side
conversation search; it needed no durable schema or authority change (the
handoff briefing extends its existing JSON blob and search reuses the
`session_events` visibility fence), so it adds no ADR. 11C added the
liveness/readiness probes, structured redaction-guarded telemetry, the
access-controlled Prometheus metrics surface, SLOs/alerts/runbooks, online
backup/restore with fail-closed pre-migration snapshots and a restore drill, the
periodic maintenance tick wiring the 11A escalation/delivery adapter, and the
systemd/PM2/container deployment profiles with canary + migration-aware rollback;
it added no durable authority (backups, telemetry, and metrics are projections
over existing durable state, and the maintenance tick only schedules existing
capabilities), so it adds no ADR.

- Add the global attention inbox, durable read/delivery cursors, deadlines, escalation, and
  Slack/Telegram notification delivery for unavailable steerers. — **11A done**: schema v18
  (`comment_mentions`, `comment_attachments`, `user_attention_reads`, and the hash-chained
  append-only `attention_escalations`/`attention_deliveries`), the `AttentionInboxStore`
  authority (cross-session aggregation fenced to active Participants, unread math from the read
  cursor, idempotent Supervisor escalation of lapsed Handoff deadlines, and idempotent fail-closed
  notification delivery through the existing outbound egress), and the `GET /api/attention`,
  `GET /api/attention/unread-count`, `POST /api/attention/read` routes. A periodic maintenance
  driver to run escalation/delivery on a schedule is deferred to 11C operations.
- Complete chat pagination, search, unread/read state, mentions, artifact attachments, and
  virtualization. — **11A done** for pagination (sequence-ordered `session.events`), unread/read
  state (attention read cursor), `@mention` parsing/resolution feeding the inbox, bounded artifact
  attachments, mention rendering, and client windowing/virtualization in `ConversationTimeline`.
  Server-side bounded conversation search — **11B done**: the visibility-fenced, sequence-paginated
  `session.conversation-search` kernel query over comment bodies, wired into the conversation surface.
- Complete mobile navigation, accessibility, structured handoff artifacts/blockers, and operator
  error states. — **11B done**: an off-canvas mobile nav plus responsive `(app)` layouts; an
  accessibility pass (landmarks, skip link, labelled controls, `aria-live`, keyboard-operable
  dialogs); structured handoff briefings (summary, current state, first-class blockers, next steps,
  evidence/Run links) captured on offer and shown to the accepting Participant and in the attention
  inbox; and App Router error boundaries (`error`, `global-error`, `not-found`) with a single
  non-leaking operator error surface for auth-expired, permission-denied, session-gone,
  runtime-unavailable, offline, and server states. Blockers are captured, bounded, and surfaced
  first-class as an immutable part of the accountable briefing; durable per-blocker _resolution_
  state (mutating individual blockers after the offer) is intentionally deferred because it conflicts
  with the append-only briefing model — a handoff resolves atomically on accept/cancel/expire.
- Add live/readiness probes, structured telemetry, metrics, SLOs, alerts, and incident runbooks. —
  **11C done**: `/health` (liveness, minimal, non-leaking) and `/api/health/ready` (readiness —
  SQLite reachable + expected schema + integrity, and the Secret Broker when configured; fails
  closed with a bare non-leaking status); a structured JSON telemetry logger with levels,
  request/trace correlation ids, and a redaction guard that drops secret-named fields and scrubs
  bearer/JWT values (the audit log now routes through it); an access-controlled Prometheus
  `/api/metrics` (token-or-admin, 404 otherwise) covering request rate/latency/errors, PTY session
  counts, outbox/worker lag, session counts, and the Gate-5/Gate-8 counters; and SLOs, alert rules,
  and incident runbooks in `docs/production-readiness/` (`slos.md`, `alerts.md`, `runbooks.md`).
- Add online backup/restore, pre-migration snapshots, restore drills, retention, and capacity
  controls. — **11C done**: online backup via SQLite's Online Backup API (never a live-WAL copy),
  verified restore, an automatic fail-closed pre-migration snapshot hooked into the migration
  dispatcher (`VACUUM INTO` before any migration mutates the database), a restore drill that backs
  up → restores → verifies integrity + the Phase 10 event chain over every session, rotation/
  retention of backups/snapshots/recordings, and documented capacity limits
  (`docs/production-readiness/backup-restore.md`).
- Ship production PM2/systemd/container profiles, safe restart behavior, canary rollout, and
  migration-aware rollback. — **11C done**: `deploy/terminalx.service` (systemd, `KillMode=process`
  so a restart never kills live tmux/pty), `deploy/ecosystem.config.js` (PM2 fork mode), a hardened
  container (readiness healthcheck, resource ceilings, Secret Broker sibling template), the periodic
  maintenance tick driving 11A escalation/delivery through the concrete production adapter plus
  rotated backups, graceful drain consistent with `graceful-shutdown`, and a canary +
  migration-aware rollback procedure with a startup rollback guard that refuses an older binary
  against a newer schema (`docs/production-readiness/deployment.md`, `canary-rollback.md`).

### Phase 12 — Adversarial verification and release

- Run local-auth multi-user browser tests across Chromium, WebKit, and mobile viewports.
- Run real Daytona integration, destructive-race, escape, secret-exfiltration, and restart tests.
- Complete OWASP/STRIDE, dependency/container, differential, accessibility, load, and maturity
  reviews with no P0/P1 findings.
- Verify signed images, SBOM/provenance, SemVer release artifacts, backup restore, canary, and
  rollback.
- Enable the production multiplayer profile only after every release gate is evidenced closed.

## Release-gate ownership

| Gate                        | Owning phases | Current state                                                                  |
| --------------------------- | ------------- | ------------------------------------------------------------------------------ |
| 1. Runtime truth            | 5–7           | Gate 1a complete; Gate 1 open                                                  |
| 2. Hosted isolation         | 7             | Open                                                                           |
| 3. Brokered secrets         | 8             | Mechanism + hermetic evidence complete; real-runtime evidence pending Phase 12 |
| 4. Approval provenance      | 9             | Mechanism + hermetic evidence complete; real-runtime evidence pending Phase 12 |
| 5. Authoritative limits     | 9             | Mechanism + hermetic evidence complete; real-runtime evidence pending Phase 12 |
| 6. YOLO challenge           | 9             | Mechanism complete and unexposed; real-runtime evidence pending Phase 12       |
| 7. Emergency recovery       | 10            | Mechanism + hermetic evidence complete; real crash/restart pending Phase 12    |
| 8. Event/evidence integrity | 10            | Mechanism + hermetic evidence complete; real-runtime evidence pending Phase 12 |

External-pilot readiness additionally requires Phase 11 operations and Phase 12 release evidence.
No development adapter, warning, feature flag, or manual operating procedure can substitute for a
closed security gate.
