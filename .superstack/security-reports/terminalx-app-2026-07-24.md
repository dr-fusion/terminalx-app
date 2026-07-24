# TerminalX comprehensive security review — 2026-07-24

## Scope and verdict

- **Mode:** Comprehensive, full repository and deployment surface
- **Baseline commit:** `b744605dbe6d3ea85492d4f5fc27684b0beecc30`
- **Confidence gate:** 2/10; findings below are retained only when code paths were traced
- **Verdict:** **NO-GO for external pilots or untrusted team/guest execution**

The collaboration kernel is a strong preproduction foundation. All eight hosted-execution release
gates are nevertheless open or partial. The production-baseline branch fixes confirmed build/auth,
dependency, container, credential-log, and CI supply-chain defects; it does not make LocalTmux a
Sandbox or open Agent Run mutations.

## Phase 0 — Architecture and stack

| Area             | Implementation                                                             |
| ---------------- | -------------------------------------------------------------------------- |
| Language/runtime | TypeScript, Node.js 24 LTS target                                          |
| Web framework    | Next.js 16 App Router with a custom Node HTTP/WebSocket server             |
| Persistence      | Local JSON stores plus better-sqlite3 for Team Sessions and Telegram audit |
| Authentication   | HMAC JWT; local/password/Google modes; device-scoped pairing tokens        |
| APIs             | Next REST handlers plus legacy and canonical WebSockets                    |
| Execution        | LocalTmux development adapter; Daytona hosted adapter not implemented      |
| Deployment       | Docker/Compose and setup/PM2 path; GitHub Actions publishes GHCR images    |

Primary trust zones are browser/API client, Next Proxy/routes, custom server, Team Session SQLite,
Runtime worker/adapter, Sandbox supervisor, secret manager/proxy, and external connectors.

## Phase 1 — Attack surface census

High-impact entry points:

- HTTP listener and Telegram webhook in `server/index.ts:597-781`.
- Legacy terminal/log/file WebSockets and canonical Team Session WebSockets in `server/index.ts` and
  `server/team-session-websockets.ts`.
- Authentication, users, settings, upload, file, workspace, session, GitHub, Telegram, and Team
  Session route handlers under `src/app/api`.
- Shell, tmux, PTY, setup scripts, repository worktrees, git/GitHub operations, and provider login
  flows.
- Outbound GitHub, Google, Telegram, model/CLI, package, git, and future Daytona traffic.

Canonical Team Session HTTP has strong body, origin, idempotency, and actor checks in
`src/lib/team-sessions/http.ts:383-465,748-785`. Legacy routes are less uniform.

## Phase 2 — Secrets archaeology

- No private-key marker or common live-token prefix was found in tracked source.
- Git history filename inspection found no committed `.pem`, `.key`, credential, or secret file.
- `.env*`, `data/`, `.pem`, generated JWT secrets, and local state are ignored.
- Secret-scanner binaries were not installed locally; Phase 12 must add CI history/image scanning.
- Raw GitHub and Telegram credentials are still available to control-plane application code, and
  same-UID LocalTmux shells can reach the control-plane boundary. This is a design failure even
  without committed secrets.

## Phase 3 — Dependency supply chain

Baseline `npm audit --omit=dev` found three high-severity production packages, including an affected
Next Proxy authorization boundary, Sharp/libvips, and brace expansion. The production-baseline
branch pins Next `16.2.11`, overrides Sharp `0.35.3`, updates safe transitive versions, moves the
runtime TS executor into production dependencies, and produces a zero-finding
`npm audit --include=dev` result.

Phase 12 must repeat npm, container, SBOM, license, and provenance scans against the release digest.

## Phase 4 — CI/CD security

Baseline weaknesses were mutable action tags, a mutable/non-LTS image, single-stage image with
build tools/dev dependencies, broad host-home mount, no SBOM/provenance, and secret material in
container logs.

The production-baseline branch:

- Pins every GitHub Action to a 40-character commit.
- Sets default `contents: read` permissions and job timeouts/concurrency.
- Pins a Node 24 multi-architecture image digest.
- Uses matching build/runtime stages and prunes development dependencies.
- Drops capabilities, enables no-new-privileges/read-only root, and removes the host-home mount.
- Stops logging generated passwords and supports `_FILE` secret injection.
- Publishes SBOM and maximum provenance.

Image signing, protected environments, SemVer release promotion, canary/rollback, and independent
artifact verification remain Phase 11–12 work.

## Phase 5 — Infrastructure shadow surface

No Terraform/Kubernetes/cloud deployment definition is present. Operational state exists in local
volumes, JSON, SQLite/WAL, tmux servers, worktrees, external OAuth/Telegram configuration, GHCR,
and operator-specific PM2/systemd configuration. Backups, restore drills, migration gates,
readiness, alerts, and a checked-in safe systemd unit are missing.

## Phase 6 — Webhooks and integrations

- Telegram checks its configured secret-token header before processing.
- GitHub webhook code has HMAC verification and tests.
- Replay/idempotency and tenant binding must be revalidated in Phase 8's unified Connection model.
- Outbound calls require consistent timeouts, circuit breaking, destination policy, and correlation
  identifiers.

## Phase 7 — LLM and agent security

Agent output can drive shell/tool activity. Current LocalTmux executes under the control-plane UID,
so prompt injection can become control-plane secret/filesystem/process access. The only acceptable
production boundary is an isolated Daytona Sandbox supervisor that verifies signed capabilities,
uses fixed harness launch arguments, obtains credentials through a scoped proxy, enforces egress and
budgets, and emits non-revealing receipts/events.

## Phase 8 — Skill supply chain

The repository contains no project-local agent skill package and does not ship the operator's
Codex/Claude skill directories in its Docker context. Operator-installed skills remain outside the
TerminalX application artifact. Phase 12 should verify production Sandbox images contain only the
approved supervisor and harness artifacts with signed provenance.

## Phase 9 — OWASP findings

### CRITICAL TX-SEC-001: build-time/runtime authentication split

**Confidence:** 10/10

**Category:** A01/A07, STRIDE spoofing/elevation

**Baseline evidence:** `next.config.ts:3-9`, Docker build ordering, and compiled bundle inspection

Next `env` compiled `TERMINALX_AUTH_MODE` into route/Proxy bundles while the custom server read the
runtime value. A default build could therefore treat anonymous REST callers as admin-like while the
custom WebSocket server accepted JWTs under local auth. The chain reached pairing-code creation and
admin JWT redemption.

**Status:** Remediated on the production-baseline branch by removing the compile-time export. The
built bundle now retains `process.env.TERMINALX_AUTH_MODE` reads. Static and route-boundary tests
were added.

### CRITICAL TX-SEC-002: public path prefix exposed pairing issuance

**Confidence:** 10/10

**Category:** A01/A07, STRIDE spoofing/elevation

**Baseline evidence:** `src/middleware.ts:23-39,66-70`, pairing issuance/redemption routes

`/api/auth/pair` used prefix matching and also matched `/api/auth/pairing-codes`. In password mode,
the issuance handler treated an absent identity as single-user admin and returned a redeemable code.

**Status:** Remediated with exact public paths, canonical actor verification inside issuance/device
handlers, no-store responses, trusted-proxy rate-limit handling, and hostile-prefix/spoof tests.

### CRITICAL TX-SEC-003: LocalTmux collapses tenant/control-plane/secret isolation

**Confidence:** 10/10

**Category:** A01/A02/A04/A05, STRIDE disclosure/tampering/elevation

**Evidence:** `src/lib/tmux.ts:195-211`, `src/lib/pty-manager.ts:110-157`,
`docs/multiplayer/phase-4-release-gates.md:8-11`

Server and shell share an OS identity, process/filesystem boundary, and control-plane data. A guest,
malicious repository, or prompt injection can potentially access signing/integration data, SQLite,
other sessions, inherited sockets, and unrestricted network.

**Status:** Open. Container hardening reduces host impact but cannot make LocalTmux multi-tenant.
Close with Daytona isolation and credential proxying; keep LocalTmux trusted-development only.

### HIGH TX-SEC-004: stale/revoked claims on legacy routes

**Confidence:** 9/10

**Category:** A01/A07

**Evidence:** full checks in `src/lib/auth.ts:137-177`; baseline Proxy only signature/expiry;
legacy route examples `src/app/api/users/route.ts`, `src/app/api/settings/route.ts`

Logged-out, revoked-device, deleted, demoted, or de-allowlisted tokens could retain projected legacy
privileges until expiry.

**Status:** Partially remediated. Proxy now uses `resolveRequestActor()` for live verification and
bearer logout revokes valid bearer tokens. Phase 6/11 must migrate every privileged handler to
fresh actor resolution so Proxy is never the sole authorization layer.

### HIGH TX-SEC-005: unsigned/mutable evidence and unavailable Runtime truth

**Confidence:** 10/10

**Category:** A08/A09/A10, STRIDE tampering/repudiation

**Evidence:** `src/lib/team-sessions/sqlite.ts:2254-2267`,
`src/lib/team-sessions/module.ts:3924-3974`, Gate 1/8 docs

Human Run intent still mutates lifecycle internally without a hosted enforced receipt; Session
events/evidence are not globally append-only, hash-chained, or signed.

**Status:** Open behind browser/HTTP capability gates. Close in Phases 6 and 10.

### HIGH TX-SEC-006: URL WebSocket credentials

**Confidence:** 9/10

**Category:** A02/A07

**Evidence:** `server/index.ts:125-136`

Legacy WebSockets accept `?token=`, exposing bearer credentials to request, proxy, analytics, and
support logs. Origin checks also permit absent Origin for compatibility.

**Status:** Open. Replace with Authorization or a short-lived one-use WS ticket and require an
explicit native-client path.

### MEDIUM TX-SEC-007: permissive production CSP

**Confidence:** 9/10

**Category:** A02/A05

**Evidence:** `next.config.ts` allows `unsafe-inline`, `ws:`, and `wss:` broadly.

**Status:** Open. Introduce nonce/hash scripts and a production public-origin-specific connect
policy after validating terminal/WASM behavior.

## Phase 10 — STRIDE model

| Component                   | Primary threats | Current mitigation                                                            | Required closure                                                          |
| --------------------------- | --------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Browser/API → control plane | S/T/E           | JWT, origin/idempotency/body guards, current actor checks on canonical routes | Canonical actor checks on every privileged route; WS tickets              |
| Team Session SQLite         | T/R/D           | Transactions, constraints, leases, immutable referenced events                | Backup/restore, hash chain/signatures, external retention, HA/load tests  |
| Runtime command path        | S/T/R/E         | Exact contracts and Gate 1a executor/journal                                  | Production signer, workers, receipts, follow cursor, compensation         |
| Daytona Sandbox             | S/I/D/E         | Not implemented                                                               | Separate principal/namespaces, egress/quotas, private handles, supervisor |
| Credential proxy            | S/I/E           | Not implemented                                                               | Opaque handles, destination grants, non-reveal, rotation/revocation       |
| Slack/Telegram/GitHub       | S/T/R/I         | Existing HMAC/secret checks and encrypted GitHub tokens                       | Unified tenant connection model, replay/delivery cursors, scoped secrets  |
| CI/release                  | T/R             | Tests and GHCR SHA image                                                      | Signed SemVer promotion, protected environment, canary/rollback proof     |

## Phase 11 — Data classification

| Class              | Examples                                   | Current location                 | Production requirement                                                      |
| ------------------ | ------------------------------------------ | -------------------------------- | --------------------------------------------------------------------------- |
| Identity/PII       | usernames, emails, Telegram IDs            | JSON/SQLite/events               | Minimize projections, encrypt/retain/delete by policy                       |
| Credentials        | JWT, OAuth, bot tokens, private keys       | env/files/encrypted records      | Secret manager + opaque handles + scoped proxy; never Sandbox/model-visible |
| Business/source    | repositories, terminal/chat content, diffs | workspace/tmux/SQLite/recordings | Tenant isolation, encryption, access audit, retention/export                |
| Authority/evidence | grants, approvals, receipts, events        | SQLite                           | Signed immutable snapshots, hash chain, external retention                  |
| Usage/financial    | model spend/tokens/runtime time            | unavailable                      | Canonical receipt-backed accounting and limits                              |

## Phase 12 — Verification and false-positive handling

- The build-time auth and public-prefix chains were traced end-to-end.
- Dependency findings came from the installed production graph and were removed by pinned versions.
- Test credentials, example values, local HTTP, build warnings, and lint findings were not reported
  as vulnerabilities.
- LocalTmux is not called a vulnerability merely for being local; it is a release blocker only for
  the explicitly requested untrusted multiplayer/guest production use.

## Phase 13 — Remediation roadmap

### P0

1. Merge the production-baseline fixes and validate the same image under every auth mode.
2. Complete Phase 6 Runtime truth and Phase 7 Daytona isolation.
3. Complete Phase 8 brokered secrets before any guest/untrusted Sandbox pilot.
4. Close Gates 4–8 with adversarial race, replay, budget, YOLO, recovery, and evidence tests.

### P1

1. Canonicalize all privileged route authorization and remove URL credentials.
2. Add readiness, immutable audit export, metrics/alerts/runbooks, backup/restore, and safe release.
3. Tighten CSP and integration/network policies.

### P2

1. Add automated secret/SAST/container/license scans and periodic dependency review.
2. Add coverage, property/mutation, browser, accessibility, load, and chaos gates.

## Eight release gates

| Gate                     | Status                                   |
| ------------------------ | ---------------------------------------- |
| Runtime truth            | Gate 1a foundation complete; Gate 1 open |
| Hosted isolation         | Open                                     |
| Brokered secrets         | Open                                     |
| Approval provenance      | Open                                     |
| Authoritative limits     | Open                                     |
| YOLO challenge           | Open and unexposed                       |
| Emergency recovery       | Partial foundation; open                 |
| Event/evidence integrity | Open                                     |

## Confidence calibration

- Total retained findings: 7
- Critical: 3, average confidence 10/10
- High: 3, average confidence 9.7/10
- Medium: 1, confidence 9/10
- False positives explicitly filtered: 5 categories
- Mode: Comprehensive

Security sign-off requires all eight gates, Daytona escape/destructive-race tests, seeded-canary
secret-exfiltration tests, multi-user browser tests, a clean dependency/container scan, restore and
rollback proof, and a fresh differential review of the final release candidate.
