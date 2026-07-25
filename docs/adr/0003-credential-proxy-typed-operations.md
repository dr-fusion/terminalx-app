---
status: accepted
---

# Credential Proxy: typed, destination-scoped operations inside the broker boundary

## Context

[ADR 0001](0001-non-revealing-credential-boundary.md) requires that raw
credentials never become readable through the agent, shell, logs, artifacts, or
model output, and [ADR 0002](0002-secret-broker-registration-protocol.md) built
the Secret Broker: a distinct, non-exporting process that owns credential
material and registers opaque **Credential Handles**. 8C deliberately shipped
**no** operation that _uses_ a credential.

Slice 8D must let approved outbound provider requests be performed with a
Credential Handle — a Telegram `sendMessage`, a Slack `chat.postMessage` — while
keeping the credential unreadable by the caller. This is the **Credential
Proxy**: "the destination-scoped effect boundary that uses a Credential Handle
to perform or sign an approved request without revealing the credential to the
caller" ([`CONTEXT.md`](../../CONTEXT.md)).

Three forces shape the design:

1. **The credential value may never enter the main process.** Only the broker
   boundary can attach an `Authorization` header or a bot-token path segment.
2. **A generic "HTTP request with a credential" primitive is unsafe.** If the
   caller could choose the URL, method, headers, or body, the credential
   boundary would degrade into a confused-deputy SSRF gadget: the caller could
   aim the credential at any destination or smuggle it back out in a crafted
   request.
3. **Every send is a fresh effect, not a durable capability.** 8B established
   that an `OutboundBindingResolution` / `InboundAttributionResolution` snapshot
   is short-lived attribution, not authority; each send must revalidate the
   applicable fences.

## Decision

### The proxy runs inside the Secret Broker process, on a sibling socket

The proxy executes in the **same non-exporting process** as the broker,
served on a sibling Unix domain socket (`proxy.sock`) inside the same `0700`
broker root, under the **same `SO_PEERCRED` peer-credential admission** as the
registration socket. The alternative — a separate sibling process — was
rejected: the proxy must read broker-private sealed material and reveal it with
the broker-root at-rest key to attach a header. A separate process would have to
be handed that material or that key, re-introducing an export path that ADR 0001
forbids. Same-process, sibling-socket composition keeps the credential and the
at-rest key inside one address space and reuses the broker's transport and
admission logic unchanged (the transport now accepts an injected connection
runner so the same admission serves a second protocol).

The credential-use seam is a single broker-private store method,
`getActiveSecretMaterial(handleId)`, that returns stored material only for an
`active` handle. Its result never crosses the protocol boundary; the closed
response guard (below) makes returning it over the wire impossible.

### A typed, closed operation registry — no generic HTTP-with-credential

There is **no** operation that takes a caller-supplied URL, method, or headers.
Instead there is a closed registry of named **Typed Provider Operations**
(`telegram.sendMessage`, `telegram.editMessageText`, `telegram.getFile`,
`telegram.downloadFile`, `slack.chat.postMessage`, `slack.chat.update`,
`slack.conversations.info`). Each entry declares its provider, an exact
destination host (`api.telegram.org`, `slack.com`), the HTTP method, the
credential placement, a bounded and validated parameter schema, and a bounded
response projection. The caller may only name an operation and supply validated
parameters; path segments are fixed constants (or, for `downloadFile`, a
strictly validated `file_path` that cannot traverse out of the credential-scoped
prefix). This eliminates the SSRF/confused-deputy class by construction.

### No exposure, by construction

- The proxy result is a **closed envelope** (`assertClosedProxyResponse`): a
  runtime guard rejects any result carrying a field outside the allowlist, so a
  result that tried to carry an `authorization`, `token`, or `url` field is
  rejected before serialization — the same discipline as the 8C
  `assertClosedResponse`.
- Raw provider responses are **projected**, never forwarded: only the
  operation's allowlisted fields are copied out. A poisoned upstream field
  (echoed token, injected `secret`) is simply not copied.
- Errors are projected to **bounded, provider-independent classification
  tokens** (`provider-declined`, `rate-limited`, `authority-mismatch`,
  `timeout-ambiguous`, …). An upstream error body, a raw header, or a Telegram
  file URL that embeds the bot token is never surfaced in a result, log, or
  error. Logs carry digests and byte counts only.

### Destination scoping and fences, revalidated per send

Every proxy call carries the exact authority snapshot: Credential Handle id +
generation, Installation id + revision, Binding id + revision where applicable,
and the expected provider and authority (`expectationDigest`). Before attaching
the credential the proxy revalidates, against broker-durable state, that the
handle is `active`, that its provider matches the operation's destination, and
that its stored `expectationDigest` matches the presented one. A revoked or
rotated-away handle fails the active check; a stale installation revision or a
different authority target resolves to a different `expectationDigest` and fails
closed with an audited `denied` result — the credential is never attached.

### Outbound accounting

Each call is durably recorded in a broker-side, **append-only** accounting log
(a separate `0600` SQLite database with UPDATE/DELETE triggers that RAISE), and
the same facts are returned in the typed result: request byte count (serialized
body + non-credential headers — credential bytes are always excluded), response
byte count, operation, destination, result class, ambiguity, timestamps, and the
authority identifiers (with a digest of the full snapshot for the sensitive
parts). Rows are immutable and monotonically ordered by an autoincrement rowid.
This is the receipt source Release Gate 5 (Phase 9) will consume; 8D records the
facts but performs **no** Gate 5 reservation math.

### Injectable network client; bounded, fail-closed I/O

Network I/O happens only inside the broker, through an injectable client (real
`fetch`-based in production, hermetic fakes in tests). TLS is required (loopback
`http` is permitted only for an explicitly configured test/gateway origin),
redirects are never followed, no environment proxy is honored, the response size
cap is enforced before buffering, and timeouts are bounded. An ambiguous outcome
— a timeout after the request was dispatched — is classified
`retryable` + `ambiguous` and recorded as ambiguous, never silently dropped.

## Consequences

- No API path can read or return credential material; the boundary is the
  process, the protocol is non-exporting, and the operation set is closed.
- The confused-deputy/SSRF class is eliminated: a caller can only invoke a named,
  host-pinned, parameter-validated operation.
- **Deliberately closed in 8D.** No caller migrates onto the proxy — the legacy
  Telegram path is unchanged, no HTTP route exposes the proxy to browsers, and
  `brokeredCredentials` / `proxyOnlyEgress` remain `false`, so Release Gate 3
  stays open. The `onepassword-connect` broker kind holds only an external
  reference and is not resolvable for use in 8D (it fails closed with
  `unsupported-credential-kind`); resolving external references for use, real
  provider adapters and least-privilege scopes (8E), hosted enforcement evidence
  (8F/8G), and Gate 5 reservation math (Phase 9) remain out of scope. A crash
  strictly between an outbound send and its accounting insert can re-send on a
  fresh retry (at-least-once); this is why ambiguous outcomes are surfaced rather
  than hidden.
