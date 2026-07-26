# Differential review vs the 2026-07-24 maturity baseline — 2026-07-26 (Phase 12)

This diffs the current branch against `maturity-assessment-2026-07-24.md` (assessment point
`b744605…`, overall **1.8/4.0**) and Phase 11 completion, recording what Phase 12 changed in-repo
and what remains gated on the real hosted runtime.

## What changed since the baseline assessment

The 2026-07-24 baseline predates Phases 8–11 completion and Phase 12. Between it and this review:

- **Gates 3–8 mechanisms + hermetic evidence landed** (Phases 8–10); Phase 11 added the product,
  attention inbox, mobile/a11y, and operations (probes, telemetry, metrics, SLOs/alerts/runbooks,
  backup/restore, deploy profiles, canary/rollback).
- **Phase 12 (this branch)** adds adversarial verification and release machinery (below).

## Phase 12 in-repo deltas (this branch)

| Area                             | Baseline (2026-07-24)       | Now                                                                                                                                                                     | Category moved          |
| -------------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| Multiplayer browser E2E          | "missing"                   | Hermetic local-auth **multi-user** suite across Chromium/WebKit/mobile: admission, steering-fence control handoff, conversation+mentions+inbox, operator error states   | Testing 3→ (toward 4)   |
| Accessibility gate               | "missing" (11B deferred)    | axe-core (vendored) pass over login/dashboard/session/conversation/inbox at desktop+mobile; **serious/critical findings fixed**                                         | Testing / Docs          |
| Real hosted-runtime tests        | "missing"                   | Real-Daytona integration + destructive-race + escape + secret-exfiltration + restart harnesses that SKIP loudly without infra and reuse the 8G canary scanner unchanged | Testing (harness ready) |
| Durable circuit breaker (Gate 5) | store existed, not composed | Composed onto the kernel with rehydrate-on-open + persist-on-mutate; close/reopen test                                                                                  | Arithmetic/Concurrency  |
| Dependency scan                  | not recorded                | `npm audit` run: **0 findings** (all + prod-only)                                                                                                                       | Components              |
| SBOM / provenance / signing      | SDK/supervisor only in CI   | SPDX SBOM for app+supervisor+**secret-broker**; SLSA/in-toto provenance predicate; cosign-style image signing script; SemVer release cutter                             | Software integrity      |
| Ops scripts verified             | shipped (11C)               | backup + restore-drill + pre-migration-snapshot + rollback-guard exercised end-to-end in-repo (dry-run/temp DB)                                                         | Auditing/Ops            |

## Findings introduced or fixed this phase

- **Accessibility (serious/critical) — FIXED in-repo**: the muted foreground `#6b7569` failed WCAG
  AA (≈3.7–4.3:1) against dark and tinted-selected backgrounds; lightened to `#899384` (≥4.5:1
  across all surfaces incl. `bg-primary/10`). A conversation-search `aria-controls` pointed at a
  not-yet-rendered listbox (invalid ARIA value) — now only set when the results region is rendered.
  The conversation timeline scroll region lacked keyboard access — added `role="log"` + `tabIndex=0`.
- **No new P0/P1 findings** were introduced. Dependency scan is clean.

## Regression check

- Full `npx vitest run`: **2322 passed, 5 skipped (real-Daytona, gated), 1 failed**. The single
  failure — `telegram-session-launch-safety.test.ts` (a timing-sensitive legacy Telegram/tmux launch
  test) — was proven **pre-existing** by re-running it on the clean baseline with all Phase 12 work
  stashed (fails identically). It is unrelated to Phase 12 scope (Telegram bot handler; mocks only
  tmux/worktree/telegram modules).
- Full `npx playwright test`: the 4 legacy auth-none failures (`diff-viewer`, `inline-comment`,
  `symlink-worktree`, `workspace-config`) were likewise proven **pre-existing** on the clean baseline
  (identical failures with all Phase 12 work stashed). The Phase 12 hermetic multiplayer + a11y
  projects (Chromium/WebKit/mobile) are **all green** (33 tests + setup).
- `npx eslint .`: **0 errors, 13 pre-existing warnings**. `npx prettier --check .`: clean.

## Net assessment movement

Testing & verification moves materially toward 4/4 for the in-repo surface (multi-user browser E2E,
a11y gate, adversarial harnesses, ops drills). Software-integrity and components gain SBOM/provenance/
signing + a clean dependency scan. The gate-blocking categories (hosted isolation, brokered-secret
real-runtime evidence) are unchanged — they are, by design, real-runtime and cannot move in-repo.
See `maturity-assessment-2026-07-26.md` for the re-scored scorecard.
