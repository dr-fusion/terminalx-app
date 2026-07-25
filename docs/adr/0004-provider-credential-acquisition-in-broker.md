---
status: accepted
---

# Provider credential acquisition happens inside the Secret Broker

## Context

[ADR 0001](0001-non-revealing-credential-boundary.md) requires that raw
credentials never become readable through the agent, shell, logs, artifacts, or
model output. [ADR 0002](0002-secret-broker-registration-protocol.md) built the
Secret Broker — a distinct, non-exporting process that owns credential material
and registers opaque **Credential Handles** — and [ADR 0003](0003-credential-proxy-typed-operations.md)
built the Credential Proxy that _uses_ a handle for a typed, destination-scoped
provider request without revealing it.

Slice 8E adds the real Telegram and Slack provider adapters. Making a connection
usable requires **acquiring** the provider credential in the first place: a Slack
OAuth `code` must be exchanged for a bot token via `oauth.v2.access`, and an
operator-supplied Telegram bot token must be validated via `getMe` and bound to a
webhook. Two forces shape where that acquisition runs:

1. **The acquired credential must never enter the main process.** If the main
   process performed the OAuth code exchange, the bot token would exist in
   agent-reachable address space before it could be sealed — exactly the exposure
   ADR 0001 forbids.
2. **Webhook verification needs a per-installation secret.** Slack signs its
   Events API deliveries with an app **signing secret**; Telegram authenticates
   deliveries with a per-webhook **`secret_token`**. Neither may leak to the
   caller, yet inbound deliveries must be verifiable.

## Decision

### Credential acquisition is three new closed-response operations on the broker socket

The broker gains `exchange.slack-oauth`, `exchange.telegram-bot-token`, and
`webhook.verify-slack`, served over the existing registration socket under the
same `SO_PEERCRED` admission and the same closed-response discipline
(`assertClosedResponse`). Each performs its provider network call **inside the
broker** through an injectable `ProviderExchangeClient` (real `fetch` in
production — TLS-only, redirects refused, bounded; hermetic fakes in tests), and
returns only non-secret data:

- **`exchange.slack-oauth`** runs `oauth.v2.access` inside the broker, binds the
  result to the exact expected team/app (a mismatch fails closed with
  `permission-denied`), stores the Slack signing secret sealed at-rest bound to
  the installation, seals the bot token through the **existing two-phase
  `prepare`** path, and returns only a **Registration Receipt** plus the
  non-secret installation identity (team id, app id, granted scopes, bot user id).
  The main process verifies the receipt locally against the broker's published
  key and finalizes exactly as for any registration.
- **`exchange.telegram-bot-token`** validates the operator-supplied bot token via
  `getMe`, binds it to the expected bot id, generates the webhook `secret_token`
  **inside the broker**, sets it on Telegram using the broker-only bot token,
  seals the bot token, and returns a receipt + bot identity + the **SHA-256 of
  the `secret_token`**. The main process stores only that digest and verifies
  inbound `X-Telegram-Bot-Api-Secret-Token` headers by constant-time digest
  comparison — no broker roundtrip per delivery.
- **`webhook.verify-slack`** computes the v0 HMAC with the stored signing secret
  and returns a boolean plus a ±300s replay-window check. The signing secret
  never leaves the broker.

The reuse of the two-phase `prepare` path is deliberate: the returned receipt is
an ordinary Registration Receipt bound to the same `expectationDigest` the
authority computes for the installation, so the 8B admit/finalize/abort flow and
the reconciler cover exchange registrations with no new state machine. A failure
before `prepare` leaves no broker state; a crash after `prepare` converges via
the broker's TTL reap and the main-side reconciler, exactly as ADR 0002 requires.

### The Telegram token input path is a documented residual exposure

Unlike Slack (where the broker receives only a single-use OAuth `code`), the
Telegram bot token is a long-lived secret that the operator must supply directly.
It enters the broker as an **input-only** field on one HTTPS, authenticated,
live-session-gated installation request, is used inside the broker, sealed, and
never echoed, logged, or persisted outside the broker. This residual input-path
exposure is inherent to Telegram's model (there is no OAuth code exchange) and is
accepted: the token is never returned over any socket, never written to any log,
and never stored in main-process state. The single-use OAuth `code` is likewise
treated as input-only and never persisted or logged.

### Webhook secrets are broker material, not authority state

The Slack signing secret is sealed at-rest in a broker-private store keyed by the
installation `expectationDigest`; the Telegram `secret_token` lives only long
enough to call `setWebhook` and is then discarded, with only its digest returned.
The main process therefore holds no webhook-verification secret — it either calls
`webhook.verify-slack` (Slack) or compares digests locally (Telegram).

## Consequences

- No acquired provider credential, refresh token, signing secret, or Telegram
  `secret_token` ever enters the main process or crosses a socket; the boundary
  remains the broker process and the protocol remains non-exporting.
- Installation acquisition composes with the existing two-phase registration,
  receipt verification, and reconciliation unchanged.
- Wiring the broker to the 8B authority end to end surfaced and fixed a latent
  gap: the broker now mints Credential Handle ids in the authority's
  `txch_v1_` + 64-hex shape (the 8C `hnd_` format could never satisfy the 8B
  validator or the SQLite `CHECK`).
- **Deliberately still closed:** `brokeredCredentials` and `proxyOnlyEgress`
  remain `false` and Release Gate 3 stays open. 8E ships the adapters, exchange
  operations, webhook verification, replay dedup, and the end-to-end flow behind
  authenticated routes; hosted enforcement evidence (8F/8G) and Gate 5
  reservation math (Phase 9) remain out of scope.
