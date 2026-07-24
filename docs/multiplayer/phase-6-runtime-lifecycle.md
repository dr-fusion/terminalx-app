# Phase 6 Runtime lifecycle implementation status

This is the live implementation note for Phase 6. The earlier
[Phase 5 Runtime truth](./phase-5-runtime-truth.md) document is a historical foundation snapshot;
its “deliberately still closed” list should not be read as current implementation status.

## Implemented in the current slice

- Schema v5 adds a durable `starting` Agent Run and binds its immutable start command identity.
- Start, pause, resume, and stop requests enter one signed Runtime lifecycle journal. HTTP/browser
  mutations remain closed.
- Ed25519 authority issuance and verification use pinned public keys, canonical claims, a fixed
  audience, exact capability matching, and bounded expiry.
- A bounded supervisor claims only commands whose prior attempts are proven not dispatched.
- Canonical lifecycle changes occur only after a strict enforced Runtime receipt and an exactly-once
  journal effect.
- Accepted receipts and ambiguous outcomes remain unresolved as `awaiting-receipt`; they are never
  represented as enforced and are never reclaimed by the command dispatcher.
- Expired processing leases reconcile conservatively and generate an auditable revision.
- Stale enforced effects immediately invalidate mutable Run grants, quarantine the exact Runtime
  Assignment and Session authorization, and remain visibly `compensating`.
- Provider text and effect references are normalized before durable storage or public events.
- The public Run projection exposes only safe queued, awaiting-Runtime, or compensating state.

## Deliberately closed before Gate 1

This slice is not the end of Phase 6 and does not close Gate 1. Production activation remains
disabled until all of the following are implemented and tested:

- authenticated late-receipt/follow ingestion that can settle accepted receipts and restart races;
- a separately signed platform-security quarantine command and receipt-backed compensation worker;
- trusted expected effect-enforcer-set binding and durable aggregate enforcement proof;
- renewable pre-dispatch leases and Runtime timeout/abort bounds below the active lease;
- hosted handle/spec reconstruction and restart reconstruction of terminal/process write fences;
- race, crash/fault-injection, and ambiguous-timeout tests across separate database connections;
- a resolution of Gate 1's kernel-truth boundary versus Gate 2's hosted Daytona evidence.

YOLO remains unavailable. It additionally requires the one-use challenge, exact initial manifest and
grant, dispatch-time expiry/state checks, authoritative accounting, and hosted isolation assigned to
later phases.

## Truth rule

The source-of-truth order is fixed:

1. the Team Session kernel records authorized intent;
2. a Runtime worker delivers the exact signed command;
3. the journal validates and retains the exact-bound Runtime observation;
4. only enforced evidence applies the canonical lifecycle effect;
5. browser and websocket projections report the resulting durable state.

No UI acknowledgement, provider request acceptance, feature flag, warning, or development adapter
may substitute for an enforced receipt.
