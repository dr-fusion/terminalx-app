# @terminalx/secret-broker

The TerminalX **Secret Broker**: a distinct, non-exporting Node process that
registers opaque **Credential Handles** on behalf of the main server. It is the
only component that ever holds provider secret material, and it exposes no
operation whose response can return that material to a User, agent, shell,
event, log, artifact, or model response.

See `../../docs/adr/0002-secret-broker-registration-protocol.md` for the design
and `../../docs/multiplayer/phase-8-brokered-connections.md` for how 8C fits into
Phase 8.

## Boundary

- Transport is a Unix domain socket inside a `0700` broker-root directory, framed
  as NDJSON. Every accepted connection is admitted only after `SO_PEERCRED`
  (via the pinned `terminalx-secret-broker-peercred` helper) confirms the peer
  shares the broker's effective uid, and optionally the expected parent pid.
- Protocol operations are exactly: `registration.prepare|finalize|abort`,
  `rotation.prepare|finalize|abort`, `handle.revoke`, `handle.status`,
  `broker.health`. Response schemas are closed (allowlisted fields) and a runtime
  guard rejects any handler/adapter return value carrying a non-schema field.
- Registration is two-phase with durable reconciliation. `prepare` persists the
  secret plus a `pending` row in the broker-private SQLite DB (WAL, `0600`) and
  returns a single-use, Ed25519-signed **Registration Receipt**. The main
  process verifies the receipt locally and synchronously (no IPC, no network)
  using the published verification key, commits its authority row, then
  `finalize`s. A rollback `abort`s; a crash converges via TTL reap on the broker
  and the main-side reconciler.

## Approved adapters

- `oauth-envelope` — OAuth material stored broker-locally, encrypted at rest with
  AES-256-GCM under the broker-root keyfile.
- `onepassword-connect` — a reference into an external 1Password Connect server;
  network I/O happens only inside the broker. Fails closed (retryable) if the
  reference cannot be resolved.

## Building the native helper

```sh
cc -std=c17 -O2 -Wall -Wextra -Werror \
  native/terminalx-secret-broker-peercred.c \
  -o <broker-root>/terminalx-secret-broker-peercred
```

Pin its `sha256` in the daemon bootstrap config alongside `rootDir`,
`expectedOwnerUid`, and the adapter configuration.
