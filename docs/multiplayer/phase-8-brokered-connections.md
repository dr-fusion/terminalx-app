# Phase 8 brokered secrets and connections

Status: in progress. The canonical authentication identity foundation is implemented. Credential
brokering, provider connections, channel bindings, and hosted exfiltration evidence remain closed.
Release Gate 3 is open, and hosted Runtimes must continue to advertise
`brokeredCredentials: false` and `proxyOnlyEgress: false`.

## Authority boundaries

Phase 8 uses four deliberately separate authorities:

- an **Auth Identity** authenticates a canonical TerminalX User;
- an **Identity Connection** attributes one provider identity to that User;
- a **Channel Installation** is owned by a Team and represents a reviewed app installation in one
  provider tenant; and
- a **Channel Binding** is owned by a Team Session and routes one external conversation under an
  explicit inbound and outbound policy.

Slack and Telegram identities must never be inserted into `auth_identities`. Connecting a provider
does not authenticate a User, grant Team membership, admit a Participant, or grant steering. The
canonical terminology and ownership model are defined in [`CONTEXT.md`](../../CONTEXT.md), and the
non-revealing credential decision is recorded in
[`ADR 0001`](../adr/0001-non-revealing-credential-boundary.md).

## Slice 8A — canonical authentication identities

SQLite schema version 11 establishes the authentication root required before external connections
can be attributed safely:

- canonical Users, immutable provider subjects, local credential records, and one-time migration
  markers;
- generation-fenced User and Auth Identity snapshots in every authenticated JWT;
- irreversible revocation and database-enforced attribution history, including protection against
  `INSERT OR REPLACE` delete-and-reinsert behavior;
- one-time migration of existing `users.json` records while preserving User IDs, password hashes,
  and timestamps;
- canonical local-password, shared-password, and Google-subject provisioning;
- exact identity propagation through request actors, `/auth/me`, and mobile pairing; and
- redemption-time pairing revalidation so a stale or revoked identity cannot register a device or
  receive an authorized token.

Unscoped legacy `single-user` JWTs and synthetic Google JWTs fail closed and require a new login.
The local compatibility bridge is accepted only while local authentication is the configured mode.
Changing authentication mode, revoking either generation, or replacing an identity therefore
invalidates the old token immediately.

This slice intentionally does not add Slack or Telegram account linking, store provider tokens, or
enable hosted credential capabilities.

## Remaining implementation slices

- **8B — connection authority:** add generation-fenced Credential Handle metadata, Team-owned
  Channel Installations, short-lived single-use Link Challenges, User-owned Identity Connections,
  Session-owned Channel Bindings, and a redacted immutable authority ledger.
- **8C — Secret Broker:** resolve opaque handles only inside a distinct non-exporting process using
  approved secret-manager adapters. No API may decrypt or return credential material.
- **8D — Credential Proxy:** permit only typed, destination-scoped provider operations and account
  outbound bytes and results without exposing authorization headers or signing keys.
- **8E — providers:** implement Telegram and Slack installation, linking, rotation, revocation,
  webhook verification, replay protection, and least-privilege scopes without importing legacy
  plaintext provider state into the authority model.
- **8F — hosted enforcement:** bind broker and proxy policy to the exact Runtime Assignment and make
  capability activation depend on measured enforcement evidence.
- **8G — adversarial evidence:** seed canaries and prove they cannot escape through files,
  environment variables, `/proc`, terminal output, encodings, artifacts, logs, model output, or
  outbound requests.

## Acceptance boundary

Phase 8 and release Gate 3 complete only after the real hosted Runtime proves that raw credentials
are unavailable to Users, agents, shells, events, logs, evidence, artifacts, and model responses;
connection revocation and rotation are generation-fenced end to end; and proxy-only egress cannot
be bypassed. Schema coverage, mocked provider tests, warnings, or feature flags are not substitutes
for that evidence.
