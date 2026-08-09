# Phase 5 Runtime truth

Phase 5 closes the gap between an accepted Team Session command and an effect that a Runtime has
actually enforced. It is split into small internal slices so no browser action becomes reachable
before the entire enforcement path is trustworthy.

## Gate 1a: command and receipt foundation

The first slice establishes two deep modules behind narrow interfaces:

1. The post-start Runtime command execution module verifies an already-issued authority envelope,
   the exact Runtime handle and command binding, authorization generation, deadline, receipt
   identity, and lifecycle state fence. Provider details and raw provider errors stay behind this
   seam.
2. The Team Session Runtime journal durably records immutable post-start lifecycle command intent,
   delivery state, append-only receipt observations, and the exactly-once effect that may advance
   canonical Session state.

Every portable lifecycle command contract is fenced by the exact Agent Run, policy revision,
source state version, and target state version. This slice executes only the post-start subset. An
enforced receipt is valid only when its enforced fence equals that target state version. A
duplicate receipt must carry the complete original receipt and proof; a bare claim that an earlier
result was enforced is insufficient.

The journal is additive in schema v4. It supports `run.pause`, `run.resume`, and `run.stop` for an
existing exact-bound Run. It deliberately rejects `run.start`: the v3 Agent Run model has no
`starting` lifecycle, so queueing start against an already-active Run would fabricate enforcement.
Durable start needs a pending Run identity design in the next schema slice. The migration does not
reinterpret existing Runs or fabricate Runtime history for data migrated from v3.

The v4 tables are internal persistence constraints, not a second receipt-validation boundary.
Stock SQLite cannot recompute the module's canonical SHA-256 receipt digest. The later journal
writer must therefore accept only the command and detached receipt snapshots returned by the
execution module; direct or generic SQL/HTTP receipt ingestion remains closed.

## Ordering and failure rules

- The command identifier and canonical command digest remain stable across lease retries.
- At most one unresolved ordinary Runtime lifecycle command may exist for an Agent Run.
- `accepted` means only that the Runtime accepted responsibility; it is not lifecycle truth.
- Only an exact `enforced` receipt and exactly-once journal effect may advance lifecycle state.
- Replayed identical receipts are idempotent. The same identifier with different canonical content
  is a conflict and must fail closed.
- A receipt for a stale Runtime Assignment, Sandbox generation, authorization generation, policy
  revision, or Run state fence is retained for audit but cannot mutate the Run.
- Transport failures contain only a closed safe error class. Provider payloads, authority
  signatures, opaque handles, Runtime principals, cursors, and effect references never enter the
  public projection.
- Emergency stop remains a separate, stricter path and supersedes unresolved ordinary commands.

## Deliberately still closed

Gate 1a is foundation, not executable Agent Runs. The following remain unavailable:

- Run and Goal mutations over generic HTTP or browser controls;
- durable `run.start` intent and a receipt-backed `starting` to `active` transition;
- LocalTmux Agent Run start, pause, resume, or stop emulation;
- production authority signing and signature verification;
- reconstruction of a hosted Runtime handle and Runtime specification;
- durable `Runtime.follow()` event and cursor ingestion;
- receipt-backed terminal/process authorization;
- Daytona provisioning, the credential proxy, brokered secrets, approvals, limits, and YOLO.

The next slice designs the pending Run identity, then wires lifecycle requests and applies changes
only from journaled enforcement. A later slice adds the hosted Daytona adapter and durable Runtime
event supervisor. The Phase 4 release gates remain authoritative until all of those paths and their
destructive-race tests are complete.
