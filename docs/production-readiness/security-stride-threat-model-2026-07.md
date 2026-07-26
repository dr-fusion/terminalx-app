# STRIDE threat model — 2026-07-26 (Phase 12)

TerminalX is a self-hosted multiplayer control plane that drives isolated Runtimes (hosted Daytona
Sandboxes in production; a trusted LocalTmux adapter in development). The MEV-equivalent risk is two
actors/workers/runtimes racing to apply control, approval, lifecycle, or evidence effects. This
model enumerates threats per STRIDE category with the enforcing control and its evidence status.

## Assets & trust boundaries

- **Actors**: canonical Users (admin/member), guests, Runtime supervisor, platform-security operator.
- **Boundaries**: browser ↔ Next routes; Next routes ↔ Team Session kernel (SQLite); server ↔
  Runtime adapter (LocalTmux dev / hosted Daytona prod); server ↔ Secret Broker / Credential Proxy;
  server ↔ external providers (Slack/Telegram/Daytona) via scoped egress.
- **Crown jewels**: raw credentials/secret values; the durable event/evidence chain; Run/limit/
  approval authority; Sandbox isolation; the signing keys.

## Spoofing

| Threat                                            | Control                                                                                                                           | Status            |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| Forged actor identity on a request                | Canonical actor resolution + revocation/device/role/allowlist checks (`request-actor.ts`); HS256 JWT with expiry; HttpOnly cookie | OK (tested)       |
| Cross-origin cookie mutation (CSRF)               | `assertMutationOrigin` requires same-origin; Idempotency-Key required                                                             | OK (tested)       |
| Impersonated Runtime supervisor / forged receipts | Signed command authority + signed observation chain; measured capability activation (ADR 0005)                                    | OK\* real-runtime |
| Replayed pairing / invitation                     | Digest-only single-use pairing codes; one-time invitation tokens; source-JWT-bound link challenges                                | OK (tested)       |

## Tampering

| Threat                                              | Control                                                                                                                                                   | Status                        |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| Mutating durable Session events / evidence          | Append-only + hash-chained + Ed25519-checkpointed `session_events`; insert/append triggers (ADR 0007)                                                     | OK (tested)                   |
| Racing writes to control/approval/lifecycle state   | Optimistic version fences (`controlEpoch`, `accessRevision`, participant/handoff versions); idempotency keys; one terminal state on end/stop/resume races | OK (tested)                   |
| Poisoned circuit-breaker state surviving restart    | Durable circuit-breaker mirror rehydrated fail-closed on open; expired snapshots dropped (Phase 12 wiring + test)                                         | OK (tested)                   |
| Downgrade to an older binary against a newer schema | Startup rollback guard refuses it                                                                                                                         | OK (tested)                   |
| Tampered release artifact / image                   | SBOM + SLSA provenance + cosign-style signature; pinned reviewed Daytona source + verified archive                                                        | OK\* (real image in pipeline) |

## Repudiation

| Threat                 | Control                                                                                                            | Status      |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------ | ----------- |
| Actor denies an action | Actor-attributed, hash-chained, externally-retainable event chain + immutable evidence-review/goal-lineage history | OK (tested) |
| Loss of audit trail    | Structured redaction-guarded telemetry; online backup + restore drill verifying the chain over every session (11C) | OK (tested) |

## Information Disclosure

| Threat                                                                    | Control                                                                                                                                                                      | Status                              |
| ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Raw secret reaching agent/shell/logs/events/model output                  | Opaque handles only; destination-scoped credential proxy; ownership-transfer + zero-on-close credential bytes; redaction guard drops secret-named fields / scrubs bearer/JWT | OK\* (Gate 3 real-runtime)          |
| Credential exfiltration across files/env/proc/terminal/artifacts/outbound | Seeded-canary scanner across all reversible encodings + split-chunk smuggling (Phase 8G); reused unchanged by the real-Daytona exfiltration harness                          | OK (hermetic) / OK\* (real-runtime) |
| Existence/authority leakage via responses                                 | Unknown vs access-denied both 404; public-event allowlist + sensitive-field rejection                                                                                        | OK (tested)                         |
| SSRF leaking internal targets/bearer                                      | Explicit `fetch`, `redirect:"error"`, response size cap; destination-scoped egress                                                                                           | OK\* real-runtime                   |

## Denial of Service

| Threat                             | Control                                                                                   | Status                                |
| ---------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------- |
| Login brute force                  | Per-user rate limit (5/60s)                                                               | OK (tested)                           |
| Repeated failing Runtime effects   | Durable circuit breaker opens a scope after the failure threshold; fail-closed rehydrate  | OK (tested); real receipt volume OK\* |
| Oversized payloads                 | WebSocket maxPayload caps; comment/attachment bounds; response size cap on provider fetch | OK (tested)                           |
| Backup/restore capacity exhaustion | Rotation/retention of backups/snapshots/recordings; documented capacity limits (11C)      | OK (tested)                           |

## Elevation of Privilege

| Threat                                      | Control                                                                                                                                                                   | Status                                  |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| Guest/member escalating to manager/steerer  | Responsibility model + fences; single/shared steering policy; manager-only grants; capability flags computed server-side                                                  | OK (tested via multi-user E2E)          |
| Sandbox → host escape                       | Isolated filesystem/process/identity/network/resource ceilings enforced in the pinned in-Sandbox supervisor; provider-projection isolation asserted by the escape harness | OK\* real-runtime (Gate 2)              |
| Same-UID LocalTmux collapsing OS boundaries | Documented as a **development-only** adapter, never production truth; hosted Daytona is the production isolation boundary                                                 | Known, dev-only                         |
| Bypassing approval/limit authority          | Signed approval provenance; exactly-once grant consumption; durable limit reservations fail closed when accounting unavailable                                            | OK (hermetic); real receipt volume OK\* |

## Residual real-runtime items (see release-readiness-2026-07.md)

Gates 1/2/3 closure and full-volume validation of 4–8 require a real hosted Daytona org + real
provider credentials. The mechanisms above marked **OK\*** are complete and hermetically verified;
their real-runtime evidence is produced by re-running the exact machinery (including the unchanged
canary scanner and the new real-Daytona harnesses) against that infrastructure.
