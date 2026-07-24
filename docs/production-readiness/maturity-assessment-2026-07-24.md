# TerminalX code maturity assessment — 2026-07-24

## Executive summary

**Project:** TerminalX multiplayer control plane, Next.js/Node.js/SQLite/Runtime adapters

**Assessment point:** `b744605dbe6d3ea85492d4f5fc27684b0beecc30`, with the production-baseline
remediations recorded separately below

**Framework:** Trail of Bits nine-category code maturity framework, adapted from on-chain
transactions to distributed Runtime commands, receipts, budgets, and concurrency

**Overall:** **1.8 / 4.0 — Weak, strong preproduction foundation**

Top strengths:

1. Extensive state-machine, authorization, recovery, and hostile-input unit tests.
2. Strong Team Session HTTP/WebSocket validation, public-event allowlisting, and durable schema
   constraints.
3. Explicit documentation that refuses to present LocalTmux or unenforced intent as production
   Sandbox truth.

Critical gaps:

1. The eight hosted-execution security gates remain open.
2. Runtime truth modules and SQLite tables are not connected to a production worker/adapter path.
3. Monitoring, incident response, backup/restore, multi-user E2E, and release engineering are not
   yet production-grade.

## Scorecard

| Category                          | Score | Rating       | Key evidence                                                                                                                                           |
| --------------------------------- | ----: | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Arithmetic                        |     2 | Moderate     | Budget/fence/version contracts are bounded, but receipt-backed accounting and property testing are unavailable.                                        |
| Auditing                          |     1 | Weak         | Rich Session events exist; security audit logging is stdout-only and no alert/incident system exists.                                                  |
| Authentication/access control     |     1 | Weak         | Canonical Team Session authorization is strong, but LocalTmux collapses OS boundaries and legacy routes depend heavily on Proxy projections.           |
| Complexity management             |     1 | Weak         | Deep modules exist, but the Team Session module exceeds 7,000 lines and mixes many state machines.                                                     |
| Decentralization/operator control |     2 | Moderate     | Self-hosting provides operator exit/control, but production privileged-role and key-compromise procedures are incomplete.                              |
| Documentation                     |     2 | Moderate     | Architecture and release-gate risks are explicit; production runbooks, glossary, SLOs, and full user stories are missing.                              |
| Transaction ordering/concurrency  |     2 | Moderate     | Version fences, idempotency, and recovery tests are strong; hosted command/receipt races and cursor ordering remain unimplemented.                     |
| Low-level manipulation            |     2 | Moderate     | Shell/tmux/native boundaries are validated and tested, but same-UID execution and credential/process exposure prevent production isolation.            |
| Testing and verification          |     3 | Satisfactory | 1,076 tests, typecheck, lint, build, smoke, and CI pass; multiplayer browser, hosted integration, fuzz/mutation, coverage, and load tests are missing. |

## Detailed analysis

### 1. Arithmetic — Moderate (2/4)

Evidence:

- Run state versions, generations, fences, deadlines, and limits use explicit integer validation in
  `src/lib/runtime/contracts.ts` and `src/lib/runtime/runtime-command-execution.ts`.
- SQLite constrains canonical receipt fields, digests, and state transitions in
  `src/lib/team-sessions/sqlite.ts:1296-2081`.
- The read model explicitly reports `accounting-unavailable` rather than inventing usage at
  `src/lib/team-sessions/module.ts:5033-5035`.

Gaps:

- No authoritative token/spend/outbound-byte/wall-clock/action ledger is connected to Runtime
  receipts.
- No concurrency-safe reservation math, fuzzing, or invariant/property suite covers caps and
  duplicate receipt accounting.

Next level: implement Gate 5 with canonical units, explicit rounding, bounded inputs, durable
reservations, and property tests for concurrent/duplicate/crash cases.

### 2. Auditing — Weak (1/4)

Evidence:

- Team Session events are durable and actor-attributed through `TeamSessions.appendEvent()` in
  `src/lib/team-sessions/module.ts:3924-3974`.
- Public projection uses an allowlist and sensitive-field rejection in
  `src/lib/team-sessions/public-event.ts:76-128,219-260`.
- Security logging is written to stdout by `src/lib/audit-log.ts:56-64`.

Gaps:

- No centralized immutable security log, metrics, alert rules, SLOs, or tested incident response
  plan.
- Session events are not hash-chained/signed, and only journal-referenced events have mutation
  guards.

Next level: close Gate 8, export tamper-evident audit records, add alerts/runbooks, and run incident
drills.

### 3. Authentication and access control — Weak (1/4)

Evidence:

- `src/lib/request-actor.ts:28-66` performs full revocation/device/user/role/allowlist validation.
- Team Session HTTP and WebSocket paths independently resolve current actors and enforce
  actor-scoped projections.
- Baseline legacy Proxy only checked signature/expiry and projected stale claims; legacy privileged
  routes such as `src/app/api/users/route.ts:14-49` trusted those headers.
- LocalTmux and the server run as the same OS identity, documented as unsafe in
  `docs/multiplayer/phase-4-release-gates.md:8-11`.

Gaps:

- Hosted tenant isolation and brokered credentials do not exist.
- Privileged legacy route handlers need canonical actor verification rather than relying on Proxy.
- Production signing-key rotation, revocation, and compromise recovery are unspecified.

Next level: complete route migration, Daytona isolation, credential proxying, signed authorities,
and key-compromise tests.

### 4. Complexity management — Weak (1/4)

Evidence:

- Narrow modules such as `runtime-command-execution.ts`, `public-event.ts`, and
  `team-session-terminal-gateway.ts` make important boundaries independently testable.
- `src/lib/team-sessions/module.ts` exceeds 7,000 lines and owns membership, invitation, steering,
  conversation, Runtime assignment, Run, Goal, handoff, recovery, projection, and event logic.

Gaps:

- State-machine composition and transaction ownership remain concentrated in one module.
- No automated complexity budget is enforced in CI.

Next level: extract deep journal/service modules behind transactions owned by one narrow kernel;
record invariants and enforce complexity thresholds for new code.

### 5. Decentralization and operator control — Moderate (2/4)

This is a self-hosted application rather than a decentralized protocol. The relevant question is
whether an operator or hosted provider can silently trap work, credentials, or evidence.

Evidence:

- Data is self-hosted in local SQLite and operator-selected workspaces.
- Guest membership, steering, and access can be revoked.
- The product does not yet provide portable exports, migration-safe restore, or externally retained
  evidence.

Next level: document all privileged actors, require non-EOA-like managed keys/KMS for authorities,
add export/restore/retention, and ensure provider failure cannot trap repositories or evidence.

### 6. Documentation — Moderate (2/4)

Evidence:

- `docs/multiplayer/phase-4-release-gates.md` clearly states unsafe boundaries and eight release
  gates.
- `docs/multiplayer/phase-5-runtime-truth.md` accurately scopes Gate 1a and deferred work.
- README and environment examples cover legacy deployment and feature flags.

Gaps:

- No complete domain glossary, production architecture/sequence diagrams, operator runbooks,
  backup/restore guide, incident plan, or SLO catalog.
- Some deployment claims precede the multiplayer caveats and can overstate readiness.

Next level: keep the phase roadmap authoritative and add developer, operator, security, and end-user
documentation alongside each production slice.

### 7. Transaction ordering and concurrency — Moderate (2/4)

For TerminalX, ordering risk is the equivalent of MEV: two actors/workers/runtimes racing to apply
control, approval, lifecycle, or evidence effects.

Evidence:

- Idempotency keys, state versions, handoff/control epochs, receipt digests, dispatch leases, and
  duplicate recovery are extensively constrained and tested.
- The durable v4 Runtime journal is not called from production code.
- `Runtime.follow()` has no implementation, so cursor replay/conflict semantics are unproven.

Next level: make receipt settlement the sole lifecycle truth path; add multi-worker, crash-window,
stale-effect compensation, cursor conflict, and end/ensure/resume race tests.

### 8. Low-level manipulation — Moderate (2/4)

Evidence:

- Shell arguments, tmux names, filesystem roots, uploads, native PTYs, WebSocket payloads, and
  process environments have validation and negative tests.
- `src/lib/pty-manager.ts:110-157` sanitizes the tmux client environment.
- Legacy tmux creation at `src/lib/tmux.ts:195-211` still inherits the server execution identity and
  cannot isolate control-plane files or processes.

Next level: keep low-level process control inside the signed in-Sandbox supervisor, publish a
reference protocol, and differentially test adapter/supervisor behavior against the contracts.

### 9. Testing and verification — Satisfactory (3/4)

Evidence:

- The production-baseline branch passes 112 files and 1,076 tests plus TypeScript, ESLint, and a
  production Next build.
- CI runs typecheck, lint, unit tests, production smoke, and container build.
- Runtime, recovery, WebSocket, public projection, schema migration, hostile receipt, and security
  edge cases have unusually thorough unit coverage.

Gaps:

- No Team Session Playwright suite, real hosted Runtime integration suite, coverage threshold,
  mutation/fuzz tests, load test, accessibility gate, restore drill, or chaos test.

Next level: Phase 12 must cover every external entry point and critical race with measurable branch
coverage, browser/adapter E2E, property testing, fault injection, and load/SLO verification.

## Priority improvement roadmap

### Critical

1. Close Runtime truth and Daytona isolation (Phases 6–7; large).
2. Implement brokered non-revealing secrets (Phase 8; large).
3. Close approval, accounting, YOLO, recovery, and evidence gates (Phases 9–10; large).

### High

1. Add global attention/escalation, session termination, and complete chat/product flows.
2. Add readiness, telemetry, backup/restore, incident response, safe deployment, and rollback.
3. Migrate all privileged routes to canonical actor verification and eliminate URL credentials.

### Medium

1. Decompose the Team Session kernel without splitting transaction ownership.
2. Add domain glossary, diagrams, capacity guidance, retention, and contributor security guidance.
3. Add coverage, fuzz/property, mutation, accessibility, load, and browser matrices.

The detailed implementation order and release-gate ownership are in
[`roadmap.md`](./roadmap.md).
