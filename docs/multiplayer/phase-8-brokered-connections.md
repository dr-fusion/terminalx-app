# Phase 8 brokered secrets and connections

Status: in progress. The canonical authentication identity foundation, the Slice 8B local connection
authority, the Slice 8C Secret Broker process, the Slice 8D Credential Proxy, and the Slice 8E
Telegram/Slack provider adapters and end-to-end connection flow are complete. Hosted exfiltration
evidence remains closed. Release Gate 3 is open, and hosted Runtimes must continue to advertise
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
- source-JWT JTI, expiry, and device binding for mobile pairing, with the code lifetime capped to
  the source expiry and revalidation after device registration and credential signing; and
- exact signed-expiry metadata in the pairing response, so a stale, expired, or revoked identity
  cannot register a device, receive an authorized token, or be upgraded through the pre-v11 local
  compatibility bridge.

Unscoped legacy `single-user` JWTs and synthetic Google JWTs fail closed and require a new login.
The local compatibility bridge is accepted only while local authentication is the configured mode.
Changing authentication mode, revoking either generation, or replacing an identity therefore
invalidates the old token immediately.

Successful logout durably fsyncs a digest-only, per-JTI tombstone before clearing the browser
cookie. Tombstone issuance verifies the JWT signature, registered claims, expiry, and bounded 24h
lifetime independently of mutable auth mode, allowlist, identity, or device policy. Consequently a
temporarily disabled credential is still revoked, and repairing the fail-closed legacy JSON
registry cannot revive a copied bearer token. If tombstone persistence fails, logout returns an
error and does not clear the cookie or claim success.

Paired-device registration, lookup, and revocation use the same validated SQLite authority as the
canonical User. Registration commits the device row before a credential can escape, and revocation
is an irreversible timestamped transition enforced by both the authority transaction and database
triggers. There is no whole-file read-modify-write projection that another worker can use to lose a
registration or revive authority. An unavailable or invalid database fails authentication closed,
and the device APIs return an audited retryable error instead of claiming success.

Pairing-code issuance and redemption are cross-process transactional and persist only a
domain-separated SHA-256 digest of the 192-bit bearer code. The raw code is returned once after its
row commits and is never stored. Redemption atomically claims an unused code while validating its
code expiry and stored source-credential expiry before changing `consumed_at_ms`; full JTI, device,
auth-mode, allowlist, and canonical-identity authority is then revalidated before registration and
again around credential signing. A crash, second worker, or retry therefore cannot produce two
successful exchanges. SQLite also enforces bounded cleanup plus active-code limits of 3 per User
and 1,024 globally, and rolling-hour issuance limits of 12 per User and 4,096 globally.
Limit exhaustion returns an audited `429` with retry guidance, while unavailable authority state
returns an audited `503` with `no-store` on either endpoint.

The migration imports valid legacy device rows once, after canonical User provisioning, and applies
any legacy revocation tombstone before committing each row. It never imports plaintext legacy
pairing codes: outstanding two-minute QR codes must be regenerated after the upgrade. Operators
must use a stop-the-world or single-version rollout for this boundary; mixed old/new workers would
write different authorities and are unsupported.

Google OAuth keeps the pre-v11 compatibility User ID `google-${verifiedGoogleSubject}`. That ID is
derived only inside the verified-subject provisioning transaction; callers cannot nominate an ID.
This preserves ownership in both the Team Session database and durable non-SQL stores such as
devices and GitHub integrations without rewriting attribution. Each mapping is recorded in an
immutable schema-v12 `legacy_google_identity_bridges` row, and provisioning fails closed if the
derived ID is already owned by another canonical User or an existing Google identity points
anywhere else. The v11-to-v12 migration creates bridges for compatible rows. A preview-era v11
Google identity with an opaque User ID fails migration with an explicit repair requirement because
silently choosing between its SQL and non-SQL owner references could orphan or transfer authority.
Version 11 was preview-only; an affected preview operator must restore or discard that preview
database rather than expect an online authority rewrite.

This slice intentionally does not add Slack or Telegram account linking, store provider tokens, or
enable hosted credential capabilities.

## Slice 8B — connection authority

Status: complete. The local authority contracts, additive schema-v13 state, and authentication
hardening are merged as the foundation for later provider slices. This slice does not include a
usable provider connection flow or close release Gate 3.

### Credential and ownership binding

TerminalX persists opaque Credential Handle metadata and digests, never the registration receipt or
credential value. Each installation handle is bound to the exact provider, Team, external tenant,
and external application. Each optional identity-connection handle is separately bound to the exact
provider, User, Channel Installation ID and revision, external tenant, external subject, and
provider-proof replay digest. Both the normalized binding digest and its individual authority
columns must match when the handle is registered or resolved. A Team owner or admin controls the
Team-owned Channel Installation and Channel Binding; only the User who owns an Identity Connection
can revoke it.
Broker receipt digests are domain-separated by broker kind and provider: reuse is rejected within
that namespace without creating false collisions between independent broker/provider namespaces.

Secret Broker registrations and provider identity proofs are accepted only through injected,
synchronous local verifier callbacks. The authority defaults closed when either required verifier is
absent, returns no verified result, or returns data that differs from the exact expected authority
snapshot. Link issuance and completion also default closed without an injected authentication
snapshot validator. That validator rechecks the authentication mode, Google allowlist where
applicable, source-credential expiry, logout JTI, and paired-device status; the canonical User and
Auth Identity generations are re-resolved from SQLite as part of the transaction.
Every human installation, connection-revocation, and binding mutation passes this live-session
gate, not only Link Challenge issuance. Installation creation and credential rotation recheck it
again after broker verification and immediately before persisting a Credential Handle; a logout,
device revocation, mode change, or allowlist change that wins that race rolls back the transaction.

### Linking, scope, and replay fences

A Link Challenge is single use, persists only a challenge digest, and is bound to the User and Auth
Identity generations, authentication-session JTI and device provenance, Team membership version,
source-credential expiry, Channel Installation revision, and requested-scope digest. Its lifetime
must be at least 60 seconds and no more than 10 minutes, can never exceed the source credential's
remaining lifetime, and issuance requires primary authentication no more than 5 minutes old. The
authentication snapshot is validated when the challenge is issued, after provider-proof
verification, after optional broker verification, and immediately before it is consumed. Expiry or
revocation that wins either verifier race aborts the transaction and rolls back any broker-handle
row and ledger effect.

SQLite enforces durable rolling-hour issuance limits of 12 challenges per User and Installation and
512 per Installation, including challenges that are no longer active. Active challenges are also
capped at 3 per User and Installation and 128 per Installation. Requested scopes must be a subset of
the installation's reviewed scopes. Completion accepts only a canonical granted-scope set exactly
equal to the requested set, so a provider proof cannot silently broaden or narrow the resulting
connection. Provider replay IDs are persisted only as a digest namespaced by the provider, external
tenant, and external application, with one database consumption permitted for that digest.
An active link is scoped to one exact Channel Installation, so the same User may link the same
external identity through separate Team installations of one provider workspace. Historical
attribution remains globally locked to that canonical User across those installations and can never
be transferred to a different User.

An Identity Connection provides attribution to a canonical User only. It does not create or imply
Team membership, Participant admission, session access, controller or supervisor authority, or
steering rights. Inbound resolution still requires the exact active Installation, Binding, Team
Session, User, connection, policy, credential-handle, and revision snapshots.

Inbound resolution is action-specific: a directive resolves only under
`comments-and-directives`, while a comment may resolve under either comment-capable mode. Outbound
resolution likewise distinguishes mentions from all-session messages and rejects artifact-bearing
effects unless the Binding explicitly allows artifacts. These results are short-lived attribution
and routing snapshots, not durable capabilities: a later Team Session command or provider send is a
separate effect boundary and must revalidate the applicable kernel and Credential Proxy fences.
Anonymous notification/comment ingress is not handled by the linked-identity resolver and requires
a separate fail-closed adapter path in Slice 8E.

Rotating an installation credential revokes the replaced handle and outstanding challenges and
increments the Installation revision. Existing Identity Connections and Channel Bindings retain
their prior revision fence and therefore stop resolving. The User must revoke and relink the
Identity Connection, and a Team owner or admin must explicitly update the Binding policy against the
new Installation revision. Rotation never upgrades either authority silently.

### Local ledger boundary

Schema v13 adds `connection_authority_ledger` as redacted, append-only local mutation and audit
evidence. SQLite triggers add a digest-only `mutation-recorded` row for each governed table insert or
update, while authority methods add semantic human/provider events. Those semantic inserts are not
a trust boundary: a local database writer is not made trustworthy merely because the normal method
records an event. The ledger is neither signed nor hash-chained and is not the externally retainable
release evidence required by Phase 10.

There is no Slack backend adapter in this slice. The legacy host-global Telegram integration remains
separate and is not migrated, inferred, or trusted as Team/User/Session connection authority;
provider adapters and legacy retirement remain Slice 8E work.

The legacy Telegram download path rejects exact sensitive destinations and final-component symlinks
with exclusive creation. As of Slice 8E the parent-directory rename race is closed: creation is now
descriptor-relative (`openat`-style — the parent directory is opened to pin its inode and the file is
created relative to that descriptor with `O_CREAT|O_EXCL|O_NOFOLLOW`), so a same-host actor cannot
redirect the write by renaming the parent between validation and creation. See Slice 8E below for the
remaining legacy retirement re-scope.

## Slice 8C — Secret Broker

Status: complete. The Secret Broker is a distinct, non-exporting Node process (`packages/secret-broker`)
that owns credential material and registers opaque Credential Handles for the 8B authority. The design
and its rationale are recorded in [`ADR 0002`](../adr/0002-secret-broker-registration-protocol.md).

- **Distinct process, private transport.** The broker is reached only over a Unix domain socket inside
  a `0700` broker-root directory, framed as NDJSON. Each accepted connection is admitted only after
  `SO_PEERCRED` (via a hash-pinned helper, since Node exposes no `getsockopt(SO_PEERCRED)`) confirms
  the peer shares the broker's effective uid and, when configured, the expected parent pid.
- **Non-exporting by construction.** Operations are exactly `registration.prepare|finalize|abort`,
  `rotation.prepare|finalize|abort`, `handle.revoke`, `handle.status`, and `broker.health`. Response
  schemas are closed and a runtime guard rejects any handler or adapter return value carrying a
  non-schema field, so no operation can return secret material.
- **Approved adapters.** `oauth-envelope` stores OAuth material broker-locally, encrypted at rest with
  AES-256-GCM under a broker-root keyfile that never leaves the process; `onepassword-connect`
  references an external 1Password Connect server (network I/O only inside the broker, injectable HTTP
  client, fail-closed retryable errors), persisting only the opaque reference. TerminalX main-process
  state stores only handle IDs and digests, as enforced by 8B.
- **Two-phase registration with durable reconciliation.** `prepare` durably persists the secret plus a
  `pending` row (broker-private SQLite, WAL, `0600`) and returns a single-use, Ed25519-signed
  Registration Receipt binding the exact expectation. The main process verifies the receipt locally and
  synchronously against the broker's published verification key — no IPC or network inside the SQLite
  transaction — then `finalize`s on commit or `abort`s on rollback. A broker TTL-reap sweep plus a
  main-side reconciler resolve every ambiguous outcome; a rollback, uniqueness failure, crash, or
  duplicate/ambiguous message converges with no externally active orphan handle. Rotation uses the same
  flow with the `replaces` linkage: the replaced secret survives until the replacement finalizes, then
  becomes irreversibly revoked.
- **Composition.** The connection authority receives the broker receipt verifier only when a broker is
  configured and has published its verification key; production startup fails closed if a configured
  broker is not ready. Local development without a broker keeps today's behavior (connection
  installation APIs fail closed). The broker process is supervised as a separate service.

Deliberately closed in 8C: there is no operation that uses a credential (that is the 8D Credential
Proxy), no real Slack/Telegram provider adapters (8E), and no hosted enforcement evidence (8F/8G).
`brokeredCredentials` and `proxyOnlyEgress` remain `false` everywhere and Release Gate 3 stays open.

## Slice 8D — Credential Proxy

Status: complete. The Credential Proxy is the destination-scoped effect boundary that uses a
Credential Handle to perform an approved outbound provider request without revealing the credential
to the caller. It runs **inside the Secret Broker process** on a sibling Unix socket (`proxy.sock`)
in the same `0700` broker root under the same `SO_PEERCRED` admission, so the credential value and
the at-rest key never leave that address space. The design and its rationale are recorded in
[`ADR 0003`](../adr/0003-credential-proxy-typed-operations.md).

- **Typed, closed operation registry.** There is no generic "HTTP request with a credential"
  operation. The registry is a closed set of named **Typed Provider Operations**
  (`telegram.sendMessage`, `telegram.editMessageText`, `telegram.getFile`, `telegram.downloadFile`,
  `slack.chat.postMessage`, `slack.chat.update`, `slack.conversations.info`). Each declares its
  provider, an exact destination host (`api.telegram.org`, `slack.com`), method, credential
  placement, a bounded/validated parameter schema, and a bounded response projection. Path segments
  are fixed constants; the one path-bound parameter (`file_path`) is strictly validated against
  traversal. This eliminates the confused-deputy/SSRF class by construction.
- **Fences revalidated per send.** Every call carries the exact authority snapshot (handle
  id + generation, installation id + revision, binding id + revision where applicable, provider,
  and `expectationDigest`). Before attaching the credential the proxy revalidates against
  broker-durable state that the handle is `active`, that its provider matches the destination, and
  that its stored `expectationDigest` matches. A revoked/rotated handle or a stale authority target
  fails closed with an audited `denied` result and the credential is never attached.
- **No exposure, by construction.** The result is a closed envelope enforced by a runtime guard;
  raw provider responses are projected to allowlisted fields, never forwarded; errors are projected
  to bounded classification tokens. Authorization headers, signing keys, upstream error bodies, and
  the token-bearing Telegram file URL never appear in any result, log, or error. Logs carry digests
  and byte counts only.
- **Outbound accounting.** Each call is durably recorded in an append-only, immutable, monotonically
  ordered broker-side accounting log and returned in the typed result: request/response byte counts
  (credential bytes excluded), operation, destination, result class, ambiguity, timestamps, and the
  authority identifiers. This is the receipt source Release Gate 5 (Phase 9) will consume; 8D does
  not build Gate 5 reservation math.
- **Bounded, fail-closed network I/O.** Network I/O happens only inside the broker through an
  injectable client (real `fetch` in production, hermetic fakes in tests): TLS only (loopback `http`
  allowed only for an explicitly configured origin), redirects never followed, no environment proxy
  honored, response size cap enforced before buffering, bounded timeouts, and an ambiguous
  timeout-after-send classified `retryable` + `ambiguous` and recorded as ambiguous.

Deliberately closed in 8D: no caller migrates onto the proxy — the legacy Telegram path is
unchanged, and no HTTP route exposes the proxy to a browser. The `onepassword-connect` kind holds
only an external reference and is not resolvable for use in 8D (fails closed with
`unsupported-credential-kind`). Real provider adapters and least-privilege scopes (8E), hosted
enforcement evidence (8F/8G), and Gate 5 reservation math (Phase 9) remain out of scope.
`brokeredCredentials` and `proxyOnlyEgress` remain `false` everywhere and Release Gate 3 stays open.

## Slice 8E — Telegram/Slack provider adapters and end-to-end flow

Status: complete. Slice 8E turns the local authority, broker, and proxy into a usable connection
flow for Telegram and Slack, without importing any legacy plaintext provider state into the authority
model. The credential-acquisition design and its rationale are recorded in
[`ADR 0004`](../adr/0004-provider-credential-acquisition-in-broker.md).

- **Credential acquisition inside the broker.** Three new closed-response operations on the broker
  socket (`exchange.slack-oauth`, `exchange.telegram-bot-token`, `webhook.verify-slack`) perform the
  provider network call inside the broker and return only a Registration Receipt plus non-secret
  installation identity. The raw bot token, refresh token, Slack signing secret, and Telegram
  `secret_token` never cross the socket. The Slack signing secret is sealed at-rest bound to the
  installation; the Telegram `secret_token` is generated in-broker, set on Telegram, and reduced to a
  digest the main process stores. The residual Telegram token input-path exposure is documented in
  ADR 0004.
- **Provider adapters.** `src/lib/connections/providers/{telegram,slack}` implement the injected
  `verifyProviderProof` (deep-link `/start` for Telegram, Sign in with Slack OIDC for Slack — both
  bound to the challenge digest and installation identity, constructing a `VerifiedProviderIdentity`
  only from provider-verified material), webhook verification (Telegram secret-token digest
  comparison; Slack v0 HMAC via the broker), inbound normalization, and outbound send mapped to a
  typed 8D proxy operation with the exact per-send authority snapshot.
- **Least-privilege scopes.** Slack installs with `chat:write` + `channels:read` (what the typed
  proxy operations need) plus reviewed event subscriptions; identity linking uses `openid`/`profile`.
  Telegram models the bot's fixed capability set (`bot:send-message`, `bot:edit-message`,
  `bot:receive-updates`, `bot:get-file`) as reviewed scopes plus an `identity:telegram` link scope.
- **Replay protection.** Linking proofs replay-fence via the 8B provider-proof digest namespace.
  Webhooks add durable, bounded, digest-only dedup of Slack `event_id` and Telegram `update_id` per
  installation (schema v14 `provider_webhook_deliveries`, write-once with immutability triggers, plus
  a Telegram monotonic-ordinal column), the Slack ±300s timestamp window, and the Telegram monotonic
  `update_id`. Duplicate/replayed deliveries are acknowledged-but-dropped; the authoritative
  "never processed twice" guarantee is the idempotent kernel command keyed by the provider replay id,
  so a crash between processing and marking is at-least-once acknowledged and never a double Session
  event.
- **End-to-end flow.** Inbound: verified webhook → normalize → replay dedup →
  `resolveInboundAttribution` (linked path) or the separate fail-closed anonymous path
  (acknowledged/audited only when the Binding permits unlinked inbound, never a directive, never a
  Session mutation) → append a comment/directive through the kernel command surface with exact
  attribution. Outbound: a per-message delivery step resolves the Binding outbound policy (fencing
  disabled/mentions-only, artifact gating, and stale revisions), sends through the 8D proxy, and
  retries only on `retryable` within a bounded budget, never on `denied` (a rotation/revocation
  mid-flight resolves to `authority-mismatch` and is terminal). An integration test exercises install
  → link → bind → inbound comment → outbound delivery across the real broker child process with fake
  Slack + Telegram servers.

Deliberately closed in 8E: `brokeredCredentials` and `proxyOnlyEgress` remain `false`, Release Gate 3
stays open, and no provider network call in CI touches a real provider. Full retirement of the legacy
host-global Telegram integration is re-scoped to land with 8F hosted enforcement (see below): it backs
a live deployment, so 8E only hardens it (descriptor-relative download creation closing the
parent-rename race) and fences it behind the `TERMINALX_LEGACY_TELEGRAM` flag with a deprecation
startup warning; hosted Runtimes never get the legacy path because hosted enforcement composes only
the brokered path.

## Remaining implementation slices

- **8C — Secret Broker:** complete; see the Slice 8C section above.
- **8D — Credential Proxy:** complete; see the Slice 8D section above. Permits only typed,
  destination-scoped provider operations and accounts outbound bytes and results without exposing
  authorization headers or signing keys.
- **8E — providers:** complete; see the Slice 8E section above. Telegram and Slack installation,
  linking, rotation, revocation, webhook verification, replay protection, and least-privilege scopes,
  with credential acquisition inside the broker and no legacy plaintext provider state in the
  authority model.
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
