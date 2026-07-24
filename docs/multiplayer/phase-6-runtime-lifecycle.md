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
- Schema v6 binds every new policy and signed lifecycle command to the exact trusted
  effect-enforcer-set digest captured in its immutable Runtime authorization epoch. Legacy rows
  remain explicitly untrusted and cannot be claimed as production work.
- Enforced receipts require an exact-command aggregate proof and an injected verifier. Proofs bind
  a domain-separated effect-reference commitment, so raw provider references never enter verifier
  inputs. Provider references are always hashed even when their text resembles a commitment;
  restart verification uses a separate validating path for journal-owned durable commitments.
- SQLite settlement requires a synchronous local proof decision. Promise-returning verifiers fail
  closed immediately and cannot settle later against an expired dispatch or follow lease.
- The private Runtime follow journal pins one binding-scoped Ed25519 observation key, persists a
  monotonic signed cursor chain, and settles late receipts, lifecycle state, effects, follow events,
  and cursor advancement in one SQLite transaction.
- Follow and command delivery use separate renewable, version-fenced leases. Handle resolution and
  Runtime command dispatch receive live `AbortSignal`s and are bounded below the current lease;
  resolver cancellation is proven pre-dispatch while command cancellation remains uncertain.
- The final pre-dispatch renewal rechecks the complete durable Run, Session, Assignment, policy,
  Goal, authorization-epoch, enforcer-set, and time fence. A durable dispatch interlock prevents a
  current authorization from changing between that renewal and the Runtime seam, while lease
  recovery can still distinguish proven pre-dispatch work from an ambiguous dispatch.
- A validly signed bad proof is contained without creating receipt/effect truth. Unauthenticated
  malformed packets cannot use that path to quarantine a tenant Runtime.
- Schema v7 adds immutable stale-effect incidents, separately signed `safety.quarantine` commands,
  crash-safe compensation dispatch, compensation receipts/effects, and exact-source follow events.
- Platform-security compensation advances beyond every durable authorization and safety high-water
  for the exact historical binding. It cannot retire or mutate a replacement Assignment, and the
  original lifecycle command remains visibly `compensating` until enforced containment exists.
- Lifecycle and compensation receipt observations use separate signature/digest domains. One
  binding-pinned receipt-only follower handles both streams without allowing terminal output to
  starve receipt reconciliation; malformed authenticated containment observations quarantine only
  their historical stream.
- A platform-signed effect-enforcer manifest pins the exact purpose-specific Ed25519 enforcer set.
  Static restart bundles and a bounded synchronous dynamic attestation source both authenticate
  every acknowledgement digest before SQLite may create effect truth.
- A separately signed Runtime observation-key registry binds each key to the complete Runtime
  binding, authorization generation, adapter identity, and adapter configuration. Its production
  source is independent of Runtime/provider payloads.
- The process-local terminal write registry has a mandatory production bootstrap mode. The private
  kernel reconstructs a transactionally consistent SQLite snapshot, preserves authorization
  high-water across replacement Assignments, and installs it before the server constructs any
  canonical terminal gateway or Runtime worker.
- One portable supervisor composition owns lifecycle delivery, receipt follow, compensation
  materialization/delivery, write-state bootstrap, cancellation, and readiness. Adapter command and
  handle capabilities are captured from data descriptors before any dispatch interlock.
- Separate-connection tests prove singular claims and settlement, dispatch-marker crash recovery
  without redispatch, and rollback without partial leases under deterministic `SQLITE_BUSY`.

## Phase boundary and remaining release evidence

The portable Phase 6 kernel is complete and its full repository gate passes. Production activation
remains closed: the remaining Gate 1 evidence belongs to the hosted adapter work in Phase 7:

- reconstruct exact opaque hosted handles and immutable Runtime specs after process restart;
- run the portable command, receipt, follow, compensation, and write-fence semantics against the
  pinned Daytona fork rather than LocalTmux or a reference Runtime;
- prove that hosted process execution, terminal input, filesystem, identity, network, and resource
  fences remain enforced through timeouts, restarts, and replacement Sandbox races; and
- wire the complete signed trust group into the production server. The live server deliberately
  continues to expose only the LocalTmux development path until that hosted group exists.

The following evidence remains assigned to later gates and must not be presented as Gate 1 proof:

- restart-reverifiable signed-observation evidence envelopes, including privacy-safe forensic
  commitments for authenticated observations rejected during containment (owned by Gate 8);
- raw-secret unavailability and connection revocation (Gate 3); and
- approval, accounting, and YOLO enforcement (Gates 4–6).

Phase 6 can complete the portable signed Runtime-truth kernel with a reference/fake Runtime. Gate 1
remains open until Phase 7 demonstrates those semantics through the pinned hosted Daytona adapter;
that evidence does not by itself close Gate 2's isolation requirements.

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
