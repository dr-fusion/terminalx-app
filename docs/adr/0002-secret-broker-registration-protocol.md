---
status: accepted
---

# Secret Broker registration protocol: two-phase signed receipts with durable reconciliation

## Context

[ADR 0001](0001-non-revealing-credential-boundary.md) requires that application
state hold only opaque **Credential Handles** and that raw credentials never
become readable through the agent, shell, logs, artifacts, or model output. Slice
8B built the local connection authority that persists only handle metadata and a
`credentialBrokerReceiptDigest`, and that defaults closed unless an injected,
synchronous `verifyCredentialHandleRegistration` callback confirms a broker
registration. Slice 8C must supply the broker behind that callback.

Two forces shape the design:

1. **The credential boundary must be a distinct process.** Secret material and
   the keys that protect it must not live in the main server's address space,
   where an agent-reachable bug could read them. So resolution and storage happen
   in a separate, non-exporting process reached over a private channel.

2. **Registration spans two independent durable stores.** The broker owns the
   secret and its own `pending`/`active` row; the main authority owns the
   Credential Handle row in its SQLite database. A naive "insert here, then insert
   there" cannot be made atomic across the two. A SQLite rollback, a uniqueness
   failure, a crash between the two writes, or an ambiguous IPC response could
   otherwise strand an **externally active orphan handle** (a live secret the
   authority never recorded) or diverge rotation state (a replaced secret
   destroyed while its replacement never committed, or both live at once).

## Decision

### A distinct, non-exporting broker process

The broker is a separate Node process (`packages/secret-broker`) reached only
over a Unix domain socket inside a `0700` broker-root directory, framed as
NDJSON. Every accepted connection is admitted only after `SO_PEERCRED` — obtained
via a hash-pinned helper, because Node exposes no `getsockopt(SO_PEERCRED)` —
confirms the peer shares the broker's effective uid and, when configured, the
expected parent pid. The protocol operations are a closed set
(`registration.prepare|finalize|abort`, `rotation.prepare|finalize|abort`,
`handle.revoke`, `handle.status`, `broker.health`). Response schemas are
allowlisted and a runtime guard rejects any handler or adapter return value that
introduces a non-schema field, so no operation can return secret material even
by mistake. Secret material stored for the `oauth-envelope` kind is encrypted at
rest with AES-256-GCM under a broker-root keyfile that never leaves the process;
the `onepassword-connect` kind stores only an opaque external reference.

### Signed receipts verified locally, not IPC verification

The 8B authority verifies a broker registration **synchronously, locally, inside
its SQLite transaction, with no network or IPC**. That constraint rules out
"ask the broker over the socket whether this registration is valid" — an IPC call
inside the transaction would couple transaction latency and liveness to the
broker and reintroduce an ambiguous-response failure at the worst moment.

Instead, `registration.prepare` returns a single-use, Ed25519-signed
**Registration Receipt** that binds the exact
`CredentialHandleRegistrationExpectation` (provider, broker kind, usage,
authority binding, rotation linkage) as one `expectationDigest`, plus the opaque
handle id, receipt id, issuance time, and expiry. The main process verifies the
receipt against the broker's published verification key — read once at
composition time from the broker root — checking signature, expectation match,
and validity window with pure local computation. Single-use is enforced by the
authority's `UNIQUE` broker-receipt-digest column. A receipt issued for one
authority target therefore cannot be replayed against a different provider,
broker kind, usage, binding, or rotation.

### Two-phase registration with durable reconciliation

1. `prepare` durably persists the secret and a `pending` row (broker-private
   SQLite, WAL, `synchronous=FULL`, `0600`) and returns the receipt.
2. The main process verifies the receipt and commits its authority row.
3. On commit it calls `finalize`, moving the broker row to `active`.
4. On rollback or uniqueness failure it calls `abort`, deleting the pending
   secret.

Every broker mutation is idempotent by `operationId`/`handleId`/`receiptId`, so
duplicate messages and retries converge. Ambiguity is resolved two ways:

- The **broker** sweeps expired `pending` rows and reaps them to `aborted`,
  nulling their secret. This alone guarantees no externally active orphan handle
  can outlive its receipt TTL, even if the main process never runs again.
- The **main reconciler** resolves the one case the broker cannot see: a handle
  the authority committed but did not finalize. It finalizes when the authority
  row exists, and aborts only after the receipt has expired (never racing an
  in-flight transaction, whose verifier already rejects expired receipts).
  Otherwise it defers.

Rotation uses the same flow with the `replaces` linkage. The replaced secret
survives until the replacement `finalize`s; then the replaced handle becomes
irreversibly `revoked`. A crash mid-rotation converges through the same
reconciler and sweep, so the authority revision state and broker state never
silently diverge.

## Consequences

- No API path can decrypt or return credential material; the boundary is the
  process, and the protocol is non-exporting by construction.
- A rollback, uniqueness failure, crash at any step, or duplicate/ambiguous
  message converges with no externally active orphan handle and no diverged
  rotation state.
- The authority stays fully local and synchronous; broker liveness never blocks
  or corrupts an authority transaction.
- 8C deliberately ships **no** operation that uses a credential and does **not**
  close Release Gate 3. Typed, destination-scoped provider operations are the
  Slice 8D Credential Proxy; hosted enforcement evidence is 8F/8G. Hosted
  Runtimes continue to advertise `brokeredCredentials: false` and
  `proxyOnlyEgress: false`.
