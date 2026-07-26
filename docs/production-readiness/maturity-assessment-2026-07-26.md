# TerminalX code maturity re-assessment — 2026-07-26 (Phase 12)

Supersedes `maturity-assessment-2026-07-24.md` for the current branch
(`agent/phase12-verification-release`). Same Trail-of-Bits nine-category framework. This re-scores
the **in-repo** surface after Phases 8–11 completion and the Phase 12 verification/release work; it
does **not** claim closure of gates that require the real hosted Daytona runtime + provider infra.

**Overall: 2.6 / 4.0 — Moderate; strong preproduction, gated on real hosted-runtime evidence.**
(Baseline 2026-07-24: 1.8/4.0.)

## Scorecard

| Category                            | 07-24 | 07-26 | Rationale for the move                                                                                                                                                                                                                     |
| ----------------------------------- | ----: | ----: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Arithmetic                          |     2 |     3 | Durable limit-ledger reservations + circuit breaker now composed and rehydrated fail-closed; property/edge tests exist. Real receipt-volume accounting still pending.                                                                      |
| Auditing                            |     1 |     3 | Hash-chained signed event chain, redaction-guarded structured telemetry, access-controlled metrics, SLOs/alerts/runbooks, backup+restore drill verifying the chain. Centralized retention/alert delivery is operational.                   |
| Authentication / access control     |     1 |     2 | Canonical actor verification across routes, digest-only pairing/tombstones, same-origin mutation guard, multi-user E2E of admission/steering. Hosted tenant isolation + brokered credential real-runtime remain open (Gates 2/3).          |
| Complexity management               |     1 |     1 | Unchanged: the Team Session kernel is still a single very large module; no complexity budget in CI. Phase 12 added narrow modules but did not decompose the kernel.                                                                        |
| Decentralization / operator control |     2 |     3 | Online backup/restore + retention + self-verifying event export give operator exit; SBOM/provenance/signing add supply-chain control. KMS key custody is operational.                                                                      |
| Documentation                       |     2 |     3 | OWASP/STRIDE, dependency/container scan, differential review, release-readiness, SLOs/alerts/runbooks/backup docs added. Domain glossary + full sequence diagrams still thin.                                                              |
| Transaction ordering / concurrency  |     2 |     3 | Fences/idempotency/recovery strong and now include durable circuit-breaker restart semantics; multi-user race verified in-browser. Hosted command/receipt races + cursor replay at real volume pending.                                    |
| Low-level manipulation              |     2 |     2 | Shell/tmux/path/PTY validation unchanged; same-UID LocalTmux is dev-only. Real in-Sandbox supervisor isolation proof is Gate 2 real-runtime (escape harness ready).                                                                        |
| Testing & verification              |     3 |     4 | Multi-user browser E2E (Chromium/WebKit/mobile), a11y gate, real-Daytona adversarial harnesses (skip-gated), ops drills, 2322 unit tests, SBOM/release scripts. Full-volume load + real-runtime E2E still require infra (harnesses ready). |

## What is evidenced in-repo vs pending real-runtime

- **Evidenced in-repo now**: multi-user browser flows, accessibility (serious/critical fixed),
  dependency scan (0 findings), SBOM/provenance/signing scripts, circuit-breaker durable
  composition, ops backup/restore/rollback verification, hash-chained evidence.
- **Pending real hosted Daytona + provider infra**: Gate 1 (runtime truth end-to-end), Gate 2
  (hosted isolation), Gate 3 (brokered-secret measured evidence + canary rerun), and the real
  receipt-volume/crash-restart evidence for Gates 4–8. The exact machinery (including the unchanged
  canary scanner and the new real-Daytona harnesses) is ready to produce that evidence.

## Remaining priorities

1. Real hosted-Daytona runtime to close Gates 1/2/3 and produce real-runtime evidence for 4–8
   (harnesses + canary suite ready; see release-readiness-2026-07.md).
2. Decompose the Team Session kernel behind one transaction owner; add a CI complexity budget
   (the one category that did not move).
3. Add the CI image vulnerability scan step (trivy/grype) and a load/SLO verification run.
4. Domain glossary + production sequence diagrams.
