# Phase 4 Agent Run release gates

Phase 4 establishes the portable Agent Run contracts, immutable policy and Goal snapshots,
exact Runtime/approval/grant bindings, recovery state, and an actor-scoped read projection. It
does **not** make Agent Runs executable in hosted or autonomous environments. Run and Goal
mutations remain outside the generic HTTP command surface.

The LocalTmux adapter is development-only. It runs as the host user, carries the host home
directory, and cannot isolate SSH material, cloud configuration, keychain sockets, repository
secrets, filesystem reads, network access, or terminal output. It must never be described as a
Sandbox or used to satisfy the Centaur-style non-reveal guarantee.

The following gates must be closed before exposing Agent Run, approval, grant, autonomous, or
YOLO mutations:

1. **Runtime truth:** deliver exact-bound Run start/pause/resume/stop commands through a durable
   outbox, ingest idempotent Runtime receipts/events, and change lifecycle only after enforcement.
   Terminal authorization and contained process state must agree with pause/stop state.
   The internal command/receipt and durable-journal foundation is specified in
   [Phase 5 Runtime truth](./phase-5-runtime-truth.md); Gate 1 remains open until that foundation is
   wired to the Team Session kernel and a hosted Runtime.
2. **Hosted isolation:** implement the Daytona adapter and credential proxy using the public fork
   pinned to hardened production merge `f9b4dfe428d37f3d956acda4403879516aa8d923`, descended from
   upstream base `b5a5d9e78d76c8bcf351f2049620250e0f34eea4`; verify repository accessibility
   and commit ancestry during release, not only URL/SHA shape.
3. **Brokered secrets:** store opaque credential handles backed by an approved secret manager,
   inject them only at the proxy boundary, redact outputs, and make raw values/private keys
   unavailable even when a user or agent explicitly asks for them.
4. **Approval provenance:** bind approval decisions and signed grants to an immutable actor and
   capability snapshot. Canonical budgets and usage-ledger lineage must be part of the approved
   authority. Grant Review must capture exact grant-state versions and either require a fresh
   approval for reissue or model an explicit review-authorized lineage.
5. **Authoritative limits:** reserve and account wall clock, model tokens/spend, outbound bytes,
   and action counts from Runtime receipts. Fail closed at configured caps and persist circuit
   breaker state. Until this exists, the read model reports `accounting-unavailable`.
6. **YOLO challenge:** keep YOLO ineligible until a server-issued, actor/session/policy/Sandbox-
   bound, expiring, one-use confirmation and initial Action Grant are atomically consumed.
7. **Emergency recovery:** add an authenticated session-level platform-security retire/retry path
   for failures before a Run exists. Superseded in-flight Runtime effects must check durable
   current state after acting and compensate so they cannot resurrect retired resources.
8. **Event/evidence integrity:** bind Runtime events to exact Run policy/state, Goal Set, Goal
   version, cursor, and evidence digest. Make evidence review attributable and append-only.

External pilot readiness requires all eight gates, Daytona integration tests, destructive-race
tests, secret-exfiltration tests, and a security review. LocalTmux may remain available for
trusted manual development with YOLO disabled.
