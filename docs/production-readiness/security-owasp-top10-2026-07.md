# OWASP Top 10 (2021) review — 2026-07-26 (Phase 12)

Scope: the in-repo TerminalX control plane (Next.js App Router routes, the custom Node server, the
Team Session kernel, the Secret Broker / Credential Proxy packages, and the hosted-Daytona adapter).
This review is analysis against the current code; per-item status distinguishes what is enforced and
tested in-repo from what is gated on the real hosted runtime.

Legend: **OK** = controlled + tested in-repo · **OK\*** = mechanism complete, real-runtime evidence
pending Phase 12 · **N/A** = not applicable.

## A01 Broken Access Control — OK\*

- Canonical actor resolution on every request: `src/lib/request-actor.ts` performs
  revocation/device/user/role/allowlist validation; Team Session HTTP + WebSocket paths each
  independently resolve the actor and enforce actor-scoped projections (`src/lib/team-sessions/http.ts`).
- Mutations flow through one command bus (`POST /api/team-sessions/commands`) that enforces a strict
  field allowlist (`HUMAN_COMMAND_FIELDS`), rejects unknown fields, and keeps run/goal/session-end
  and platform-security commands **closed** to HTTP.
- Optimistic-concurrency fences (`accessRevision`, `controlEpoch`, `steeringRevision`, participant
  versions) prevent stale-authority writes; existence is never leaked (unknown vs access-denied both 404).
- Same-origin enforcement on cookie-authenticated mutations (`assertMutationOrigin`).
- **Verified this phase** by the multi-user Playwright suite (participant admission, steering-fence
  control transfer, non-participant 404) — `tests/e2e/multiplayer/team-session-multiuser.spec.ts`.
- Residual: hosted tenant isolation (Gate 2) is real-runtime; legacy `getUserScoping` routes
  (`/api/users`) depend on identity headers a middleware injects and are admin-only.

## A02 Cryptographic Failures — OK\*

- Auth tokens are HS256 JWT with bounded lifetime (`src/lib/auth.ts`); session cookie is HttpOnly,
  SameSite=Lax, Secure on HTTPS.
- Approval provenance and session-event checkpoints are Ed25519-signed and persisted digest-only
  (ADR 0006/0007). GitHub PATs are encrypted at rest with a master key.
- Brokered credentials are stored as opaque handles only; raw secret bytes use ownership-transfer +
  zero-on-close (`credential: Uint8Array` in the Daytona fetch API).
- Residual: production signing-key rotation/KMS custody and the real measured capability-activation
  keys are operational, pending the hosted deployment.

## A03 Injection — OK

- Shell/tmux/native boundaries are validated: tmux session names against `[a-zA-Z0-9_.-]`, file
  paths validated against `TERMINUS_ROOT` (traversal-safe), argument arrays never string-concatenated.
- SQLite access is exclusively parameterized prepared statements (`better-sqlite3`); the circuit
  breaker store, limit ledger, and event chain all bind parameters.
- React auto-escaping for all rendered content; `@mention` parsing is syntactic and resolved to
  canonical users server-side, never interpolated into a query.

## A04 Insecure Design — OK\*

- Fail-closed is the default posture: multiplayer transport is unavailable until the kernel is ready;
  capabilities (`brokeredCredentials`, `proxyOnlyEgress`) stay `false` until a valid signed
  measurement matches the exact Runtime Assignment — no config statically flips them (ADR 0005).
- Eight explicit security gates gate external-pilot readiness; no dev adapter/flag substitutes for a
  closed gate (roadmap invariant).
- Durable circuit breaker (Gate 5) now composed onto the kernel with rehydrate-on-open so a restart
  cannot silently reopen a fenced Runtime scope (`src/lib/team-sessions/module.ts`; test
  `tests/unit/circuit-breaker-durable-wiring.test.ts`).

## A05 Security Misconfiguration — OK\*

- Startup validation (`src/lib/startup-validation.ts`) refuses `auth=none` in production, requires a
  ≥32-char JWT secret, and requires an admin password on first local-auth boot.
- Readiness probe fails closed on schema/integrity/broker problems; metrics endpoint is
  token-or-admin gated (404 otherwise); telemetry logger redacts secret-named fields and scrubs
  bearer/JWT values (11C).
- A startup rollback guard refuses an older binary against a newer schema.
- Residual: hardened container image + image scan step (see dependency-and-container-scan doc).

## A06 Vulnerable & Outdated Components — OK

- `npm audit` (all + prod-only): **0 vulnerabilities** (see dependency-and-container-scan-2026-07.md).
- CI gates on `npm audit --omit=dev --audit-level=high`. SBOMs generated for app + supervisor +
  secret-broker (Phase 12).
- Residual: no image vulnerability scan step in CI yet (itemized).

## A07 Identification & Authentication Failures — OK

- Local/password/google/none modes with explicit validation; login is rate-limited (5/user/60s).
- Pairing codes are digest-only, single-use, issuance-limited; device registration + revocation use
  the same transactional DB as canonical users; logout revocation depends on durable digest-only
  tombstones (Slice 8B).

## A08 Software & Data Integrity Failures — OK\*

- Session events are append-only, hash-chained, Ed25519-checkpointed, and export-verifiable
  (ADR 0007). Grant consumption is exactly-once (`grant_consumptions`).
- Release integrity (Phase 12): SPDX SBOM + SLSA/in-toto provenance predicate + cosign-style image
  signing scripts (`scripts/generate-sbom.mjs`, `generate-provenance.mjs`, `sign-container-image.sh`);
  the reviewed Daytona source is pinned (`config/daytona-production-source.json`) with a verified
  release archive script.
- Residual: real signed image + attestation must be produced by the release pipeline on a real image.

## A09 Security Logging & Monitoring Failures — OK\*

- Structured JSON telemetry with request/trace correlation and a redaction guard; audit log routes
  through it; access-controlled Prometheus metrics incl. Gate-5/Gate-8 counters; SLOs/alerts/runbooks
  (11C).
- Residual: centralized retention/alert delivery is an operational deployment step.

## A10 Server-Side Request Forgery (SSRF) — OK\*

- Outbound egress for brokered connections is destination-scoped through the credential proxy; the
  Daytona fetch API uses an explicit `fetch` (never the ambient global), `redirect: "error"` (never
  forwards the bearer through a provider redirect), and a response size cap.
- The seeded-canary exfiltration suite proves the credential never reaches file/env/proc/terminal/
  artifact/outbound surfaces (Phase 8G; reused unchanged by the real-Daytona harnesses).
- Residual: full outbound-egress proof at real provider volume is Gate 3 real-runtime.

## Conclusion

No P0/P1 (critical/high) OWASP findings remain in in-repo scope. The residuals marked **OK\*** are
mechanism-complete and gated on the real hosted Daytona runtime + provider infra (Gates 1/2/3 and
the real-runtime evidence for 4–8), itemized in `release-readiness-2026-07.md`.
