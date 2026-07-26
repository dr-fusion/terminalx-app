# TerminalX release-readiness report — 2026-07-26 (Phase 12)

Branch: `agent/phase12-verification-release` (from `main` @ Phase 11 complete + ops-probe fix).

This report states, honestly and per gate, what is **evidenced-closed in-repo** versus **pending
real hosted-Daytona + provider infrastructure**, and itemizes exactly what a real environment must
run — and who must provide it — before the production multiplayer profile can be enabled.

## The honest boundary (non-negotiable)

Gates 1/2/3 CLOSURE and full-volume validation of Gates 4–8 require a **real hosted Daytona org and
real provider credentials that this environment does not have**. Nothing in this phase fabricated
that evidence: no capability (`brokeredCredentials`, `proxyOnlyEgress`) was flipped to `true`, the
production multiplayer profile was **not** enabled, and the real-runtime harnesses **SKIP loudly**
(logged reason) when the endpoint/creds are absent — they never pass vacuously. Everything below
under "evidenced in-repo" is the verification + release machinery and tests that do not require live
external infra.

## Verification results (this environment)

| Gate check                                                                       | Result                                                                                                                                                                                                  |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npx vitest run`                                                                 | **2322 passed, 5 skipped** (real-Daytona harnesses, gated), **1 failed** — `telegram-session-launch-safety.test.ts`, **proven pre-existing** on the clean baseline (stash test); unrelated to Phase 12. |
| `npx playwright test` (Phase 12 multiplayer + a11y)                              | **All green** — Chromium + WebKit + mobile: 33 tests + auth setup.                                                                                                                                      |
| `npx playwright test` (legacy auth-none project)                                 | 4 pre-existing failures (`diff-viewer`, `inline-comment`, `symlink-worktree`, `workspace-config`), **proven pre-existing** on the clean baseline (stash test); not caused by Phase 12.                  |
| `npx eslint .`                                                                   | **0 errors**, 13 pre-existing warnings.                                                                                                                                                                 |
| `npx prettier --check .`                                                         | Clean.                                                                                                                                                                                                  |
| `npm run build`                                                                  | See "build" note below.                                                                                                                                                                                 |
| `npm audit` (all + prod-only)                                                    | **0 vulnerabilities** (no P0/P1).                                                                                                                                                                       |
| Accessibility (axe-core)                                                         | login/dashboard/session/conversation/inbox at desktop+mobile — **no serious/critical**; findings fixed.                                                                                                 |
| 11C ops drill (backup / restore-drill / pre-migration-snapshot / rollback-guard) | Verified end-to-end in-repo against a temp SQLite DB.                                                                                                                                                   |

## Per-gate status (1–8)

### Gate 1 — Runtime truth · owning phases 5–7 · state: Gate 1a complete; Gate 1 OPEN

- **In-repo**: durable command/receipt journal, write-fence reconstruction, timeout reconciliation,
  and the portable kernel (Phases 5–6) are complete and unit-tested.
- **Pending real-runtime**: end-to-end Runtime truth against a real hosted Daytona Runtime (Phase 7).
  The real-Daytona integration + restart harnesses are ready (`tests/adversarial/daytona-e2e/`).

### Gate 2 — Hosted isolation · phase 7 · state: OPEN

- **In-repo**: hosted control-plane adapter, opaque handles, isolation-attestation verifier types,
  and the isolation/escape harness (provider-projection level) are present.
- **Pending real-runtime**: create/verify the reviewed Daytona fork; measured clean-binary runtime
  identity; enforced filesystem/process/identity/network/resource ceilings; proof that stale
  ensure/retire cannot resurrect/delete a replacement Sandbox. Requires the real endpoint + the
  pinned supervisor stack.

### Gate 3 — Brokered secrets · phase 8 · state: mechanism + hermetic evidence complete; real-runtime PENDING

- **In-repo**: Secret Broker, Credential Proxy, opaque handles, destination-scoped egress,
  assignment-scoped eligibility, **measured** capability activation (never a config assertion), and
  the seeded-canary exfiltration suite (Phase 8G) — all complete and hermetically verified.
- **Pending real-runtime**: the real hosted Daytona Runtime must produce the same **measured
  evidence** through this exact machinery and **rerun the canary suite unchanged**. Only then do
  `brokeredCredentials`/`proxyOnlyEgress` become `true` (per-deployment). The
  `daytona-secret-exfiltration` harness reuses the 8G scanner unchanged for this.

### Gates 4 / 5 / 6 — Approval provenance / authoritative limits / YOLO · phase 9 · mechanism + hermetic complete; real receipt-volume PENDING

- **In-repo**: Ed25519 approval provenance, grant lineage, exactly-once grant consumption, durable
  limit reservations/settlements (fail closed when accounting is unavailable), the durable circuit
  breaker **now composed onto the kernel** with rehydrate-on-open (Phase 12 wiring +
  `circuit-breaker-durable-wiring.test.ts`), unlimited-default `RunLimit`, and the unexposed
  server-issued YOLO challenge (Gate 6 "open and unexposed").
- **Pending real-runtime**: the real hosted Daytona Runtime must drive reservations, provenance, and
  YOLO consumption through this machinery at **real receipt volume**. Note: approval provenance is an
  **issuance-time** artifact by design; there is no live effect-executor that consumes grants — that
  executor is itself the Phase-7/real-Daytona deliverable (so provenance-on-consumption was correctly
  **not** force-wired).

### Gates 7 / 8 — Emergency recovery / event-evidence integrity · phase 10 · mechanism + hermetic complete; real crash/restart PENDING

- **In-repo**: append-only hash-chained signed `session_events`, self-verifying export, immutable
  evidence-review/goal-lineage history, platform-security quarantine/retire/retry, version-fenced
  `session.end`/retire/archive/retention, monotonic receipt-follow cursors. Backup+restore drill
  verifies the chain over every session.
- **Pending real-runtime**: drive the terminal lifecycle, platform-security actions, and cursor
  replay through a **real crash/restart at real receipt volume** on the hosted runtime.
  The `daytona-restart` harness covers provider-identity reconciliation across a client restart.

## Release-artifact inventory (produced this phase)

| Artifact                                                                            | Script                                                                                       | Runnable here             | Notes                                                                                            |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------ |
| SPDX 2.3 SBOM (app + daytona-supervisor + secret-broker) + checksums                | `scripts/generate-sbom.mjs <dir>`                                                            | Yes                       | Self-contained; app SBOM = 820 deps. Closes the secret-broker SBOM gap.                          |
| SLSA/in-toto build-provenance predicate + checksums                                 | `scripts/generate-provenance.mjs <out> <artifacts…>`                                         | Yes                       | Matches the CI `actions/attest-build-provenance` subject-checksums pattern.                      |
| Cosign-style image signing + SBOM/provenance attestation                            | `scripts/sign-container-image.sh <img@sha256> [sbom] [prov]`                                 | No (cosign/docker absent) | Keyless (Sigstore) or KMS key **reference**; no key material embedded. Documentation + scripted. |
| SemVer release cutter (version bump + CHANGELOG roll + annotated tag; never pushes) | `scripts/release.sh <major\|minor\|patch\|X.Y.Z> [--dry-run]`                                | Yes (dry-run verified)    | Bumps root + workspace packages; rolls `[Unreleased]`.                                           |
| Daytona reviewed-source pin + release-archive verify                                | `config/daytona-production-source.json`, `scripts/verify-daytona-runtime-release-archive.sh` | Pre-existing              | Reused unchanged.                                                                                |

House convention preserved: SPDX 2.3 JSON + Sigstore attestation (`actions/attest-build-provenance`)

- `sha256`/`checksums.sha256`. A cosign script is provided per the Phase 12 brief; it complements
  (does not replace) the keyless CI attestation path.

## Tests added this phase

- `tests/e2e/multiplayer/` — hermetic local-auth multi-user suite (Chromium/WebKit/mobile):
  `team-session-multiuser.spec.ts` (admission, steering-fence control handoff, conversation +
  mentions + attention inbox, operator error states), `accessibility.spec.ts` (vendored axe-core),
  `auth.setup.ts` (storage-state login), `local-auth-serve.ts` (seed-then-serve), helpers/config.
- `tests/adversarial/daytona-e2e/` — real-Daytona integration, destructive-race, escape,
  secret-exfiltration, restart harnesses (skip-gated; reuse the 8G canary scanner unchanged) +
  `tests/helpers/daytona-e2e-gate.ts`.
- `tests/unit/circuit-breaker-durable-wiring.test.ts` — Gate 5 durable composition close/reopen.

## What a real hosted-Daytona + provider environment MUST run (itemized) — and who provides it

The following require infrastructure this environment lacks. **Owner: the deploying operator /
platform team** (provisions the hosted Daytona org, provider credentials, and signing keys); the
harnesses and machinery to run them are already in-repo.

1. **Hosted Daytona org + endpoint + API credential + reviewed snapshot ref.** Set
   `TERMINALX_DAYTONA_E2E=1`, `TERMINALX_DAYTONA_E2E_ENDPOINT`,
   `TERMINALX_DAYTONA_E2E_API_KEY(_FILE)`, `TERMINALX_DAYTONA_E2E_SNAPSHOT_REF` (and optionally
   `..._ORG_ID`, `..._TARGET`) and run `npx vitest run tests/adversarial/daytona-e2e/`. Without these
   the harnesses skip loudly. → Gate 1 (runtime truth), Gate 2 (isolation/escape).
2. **Create + pin the reviewed public Daytona fork** from `config/daytona-production-source.json`;
   build + sign the SDK/supervisor/runner/daemon artifacts (existing `scripts/build-pinned-*`,
   `write-*-artifact.mjs`, `verify-daytona-runtime-release-archive.sh`) and derive runtime identity
   from measured clean binaries. → Gate 1, Gate 2.
3. **Compose the full pinned supervisor stack** (`server/production-daytona-hosted-runtime.ts` +
   a signed settings blob) to exercise in-Sandbox command execution for the deep escape and
   in-guest exfiltration assertions (the API-port harnesses cover provider-projection + credential
   surfaces; in-guest exec needs this stack). → Gate 2, Gate 3.
4. **Produce measured capability-activation evidence** on the real runtime and confirm
   `brokeredCredentials`/`proxyOnlyEgress` flip to `true` only on a valid signed measurement matching
   the exact Runtime Assignment, then **rerun the Phase 8G canary suite unchanged**. → Gate 3.
5. **Drive reservations / approval provenance / YOLO consumption at real receipt volume** through the
   exact Phase 9 machinery (requires the real effect-executor that consumes grants — the hosted
   runtime). → Gates 4/5/6.
6. **Run a real crash/restart at real receipt volume** and verify terminal lifecycle,
   platform-security actions, and cursor replay have no gap/fork/duplicate/regression. → Gates 7/8.
7. **Real signing keys + registry**: run `scripts/sign-container-image.sh` against the built,
   digest-pinned image with a real Sigstore identity or KMS key reference, and add a CI image
   vulnerability scan (trivy/grype) step. → release integrity / A06.
8. **Load / SLO verification** against the deployed stack (no load test exists in-repo yet).

Only after every release gate is **evidenced closed** may the production multiplayer profile be
enabled (roadmap invariant: no dev adapter, flag, warning, or manual procedure substitutes for a
closed gate).

## Build note

`npm run build` is a required release gate. It is run as part of the finish checks on this branch;
the app builds under Next 16 with the Phase 12 changes (a11y/color CSS, component ARIA attributes,
kernel circuit-breaker wiring — none change route/server contracts).
