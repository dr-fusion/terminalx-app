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

The completed phases are not an external-pilot release. LocalTmux is a trusted development
adapter, and Agent Run mutations remain closed to HTTP/browser clients.

## Remaining production phases

### Phase 6 — End-to-end Runtime truth

Close release Gate 1.

Status: complete. The implementation and deliberately closed production boundary are tracked in
[Phase 6 Runtime lifecycle implementation status](../multiplayer/phase-6-runtime-lifecycle.md).

- Add a durable `starting` Run identity and receipt-backed `run.start` lifecycle.
- Make the v4/v5 command journal the only ordinary path for start/pause/resume/stop effects.
- Add command, assignment, follow, and compensation workers with crash-safe leases.
- Reconstruct terminal/process write fences from SQLite after restart.
- Treat provider timeouts as ambiguous outcomes and reconcile the same command identity.
- Expose Run controls only after exact enforced-receipt tests pass.

### Phase 7 — Daytona hosted isolation

Close release Gate 2.

- Create and verify the public TerminalX Daytona fork based on
  `b5a5d9e78d76c8bcf351f2049620250e0f34eea4`.
- Pin the fork commit and signed SDK/supervisor artifacts with SBOM and provenance.
- Implement hosted ensure/follow/pause/resume/stop/retire and timeout reconciliation.
- Keep Daytona Sandbox identifiers adapter-private behind opaque TerminalX handles.
- Enforce isolated filesystem, process namespace, identity, network, and resource ceilings.
- Prove stale ensure/retire effects cannot resurrect or delete replacement Sandboxes.

### Phase 8 — Brokered secrets and user connections

Close release Gate 3 and complete the Slack/Telegram/credential connection model.

- Store only opaque credential handles in TerminalX state.
- Add approved secret-manager adapters and a destination-scoped credential proxy.
- Make raw tokens, private keys, and secret values unavailable to agents, shells, events, logs,
  evidence, and model output even when explicitly requested.
- Add user-scoped revocable Slack and Telegram connections with least-privilege OAuth scopes,
  tenant/channel/session bindings, provenance, rotation, and webhook replay protection.
- Run seeded-canary exfiltration tests across files, environment, `/proc`, terminal output,
  encoding, artifacts, and outbound requests.

### Phase 9 — Approval provenance, authoritative limits, and YOLO

Close release Gates 4, 5, and 6.

- Sign immutable actor, capability, policy, budget, Sandbox, and state snapshots.
- Model explicit reissue/review lineage and atomic grant usage.
- Reserve and account wall time, tokens/spend, outbound bytes, and action counts from Runtime
  receipts; fail closed when accounting is unavailable.
- Persist circuit-breaker state and optional limits, with unlimited as the explicit default.
- Implement a server-issued, expiring, one-use, actor/session/policy/Sandbox-bound YOLO challenge
  consumed atomically with the initial Action Grant.
- Support revoking all approvals for a changed Sandbox or changed execution boundary.

### Phase 10 — Recovery, evidence, and lifecycle completion

Close release Gates 7 and 8.

- Add platform-security quarantine/retire/retry before a Run exists.
- Add version-fenced `session.end`, runtime retirement, cancellation, archive, and retention.
- Persist monotonic Runtime cursors and reject conflicting replay.
- Make Session events and evidence append-only, hash-chained, signed, attributable, and externally
  retainable.
- Add immutable evidence-review history and Goal version lineage.
- Test end/stop/ensure/resume/handoff/approval races and crash recovery.

### Phase 11 — Production product and operations

Complete the externally usable application around the closed gates.

- Add the global attention inbox, durable read/delivery cursors, deadlines, escalation, and
  Slack/Telegram notification delivery for unavailable steerers.
- Complete chat pagination, search, unread/read state, mentions, artifact attachments, and
  virtualization.
- Complete mobile navigation, accessibility, structured handoff artifacts/blockers, and operator
  error states.
- Add live/readiness probes, structured telemetry, metrics, SLOs, alerts, and incident runbooks.
- Add online backup/restore, pre-migration snapshots, restore drills, retention, and capacity
  controls.
- Ship production PM2/systemd/container profiles, safe restart behavior, canary rollout, and
  migration-aware rollback.

### Phase 12 — Adversarial verification and release

- Run local-auth multi-user browser tests across Chromium, WebKit, and mobile viewports.
- Run real Daytona integration, destructive-race, escape, secret-exfiltration, and restart tests.
- Complete OWASP/STRIDE, dependency/container, differential, accessibility, load, and maturity
  reviews with no P0/P1 findings.
- Verify signed images, SBOM/provenance, SemVer release artifacts, backup restore, canary, and
  rollback.
- Enable the production multiplayer profile only after every release gate is evidenced closed.

## Release-gate ownership

| Gate                        | Owning phases | Current state                 |
| --------------------------- | ------------- | ----------------------------- |
| 1. Runtime truth            | 5–6           | Gate 1a complete; Gate 1 open |
| 2. Hosted isolation         | 7             | Open                          |
| 3. Brokered secrets         | 8             | Open                          |
| 4. Approval provenance      | 9             | Open                          |
| 5. Authoritative limits     | 9             | Open                          |
| 6. YOLO challenge           | 9             | Open and unexposed            |
| 7. Emergency recovery       | 10            | Partial foundation; open      |
| 8. Event/evidence integrity | 10            | Open                          |

External-pilot readiness additionally requires Phase 11 operations and Phase 12 release evidence.
No development adapter, warning, feature flag, or manual operating procedure can substitute for a
closed security gate.
