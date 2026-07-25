---
status: accepted
---

# Assignment-scoped credential policy and measured capability activation

## Context

[ADR 0001](0001-non-revealing-credential-boundary.md) requires that raw
credentials never become readable through the agent, shell, logs, artifacts, or
model output. [ADR 0002](0002-secret-broker-registration-protocol.md),
[ADR 0003](0003-credential-proxy-typed-operations.md), and
[ADR 0004](0004-provider-credential-acquisition-in-broker.md) built the Secret
Broker, the destination-scoped Credential Proxy, and in-broker credential
acquisition. [Phase 7](../multiplayer/phase-7-daytona-hosted-runtime.md)
intentionally advertised `brokeredCredentials: false` and
`proxyOnlyEgress: false` and stated that Phase 8 must _prove_ those guarantees
before either capability can become `true`.

Two forces shape Slice 8F/8G:

1. **A capability must reflect measured enforcement, not a configuration
   claim.** Phase 7 already establishes that "requested configuration is not
   proof of enforcement." Advertising `brokeredCredentials`/`proxyOnlyEgress`
   must therefore depend on per-deployment, per-Runtime-Assignment evidence that
   the exact running image actually enforces the boundary — not on a static pin,
   a flag, or a schema value that a mistaken deploy could flip.

2. **A brokered credential must be exercised only by the exact hosted execution
   it was authorized for.** A Credential Handle is a durable authority; a hosted
   Run that is superseded (assignee loss, fence advance, replacement Sandbox)
   must lose the ability to exercise the handle, and a different Runtime
   Assignment must never borrow it. Local human-driven flows (the 8E HTTP
   routes) are a different caller class with a different fence and must keep
   working unchanged.

## Decision

### Runtime-Assignment-scoped broker/proxy policy

Every Credential Proxy send carries an explicit **caller class**. There are
exactly two, modeled explicitly rather than inferred:

- **`human-session`** — the 8E HTTP flows. They are human-session-fenced at the
  route boundary (the connection authority's live-session gate) and are never
  assignment-fenced by the broker. Legacy frames that carry no caller are
  treated as unfenced human-session, so 8D/8E behavior is preserved.
- **`hosted-assignment`** — a hosted Run. It must present the exact Runtime
  Assignment identity: assignment id, generation, and the Sandbox identity
  digest drawn from the Phase 7 trust chain.

A broker-private, durable eligibility store records which assignment a handle is
currently pinned to (the Team Session → Channel Binding → assignment linkage,
realized broker-side as a per-handle pin) and applies the same generation-fence
discipline used elsewhere in the Runtime authority:

- first hosted use binds the handle to the presented assignment identity;
- a mismatched assignment id or Sandbox identity, or a stale (lower) generation,
  is denied with an audited `authority-mismatch` and the credential is never
  attached;
- observing a newer generation advances the fence, which revokes in-flight
  eligibility for the superseded generation; and
- a `hosted-assignment` caller reaching a proxy with no eligibility store
  composed fails closed.

### Measured capability activation

The hard `false` capability pins are replaced with evidence-derived values. The
evidence is a domain-separated, Ed25519-signed record — modeled on the Phase 7
effect-enforcer attestation — carrying three deny-by-default measurements: the
image has no ambient provider credentials (env/filesystem sweep), it reaches the
broker only via the supervisor-mediated channel, and its egress lockdown is
measured (the deny-by-default network namespace with only broker/supervisor
endpoints allowlisted that `proxyOnlyEgress` denotes). It is bound to the exact
`RuntimeBinding`, authorization generation, assignment-plan digest,
effect-enforcer policy and set digests, and the Sandbox **boot epoch**, and is
verified against the Phase 7 trust group keys with a bounded TTL.

Derivation is fail-closed: `proxyOnlyEgress` becomes `true` only when the egress
lockdown is measured, and `brokeredCredentials` becomes `true` only when all
three measurements hold. Absence, staleness (boot epoch or generation),
tampering, a foreign signing key, an assignment mismatch, or any verification
failure derives the capability `false`, and hosted credential operations fail
closed. The hosted adapter derives capabilities at handle resolution from
evidence bound to the exact Sandbox activation; without the (optional)
measured-activation seam it advertises the plan's always-false capabilities
unchanged.

### Honest evidence boundary versus Phase 12

Real-Daytona execution evidence is a Phase 12 deliverable. Slice 8F/8G build and
verify the enforcement mechanisms against the hermetic hosted-runtime harness
and the real broker/proxy modules, and the 8G canary suite proves — through a
reusable scanner that covers common encodings and split-chunk smuggling — that a
seeded canary cannot escape any observable surface. **Nothing in the codebase or
any configuration statically flips `brokeredCredentials`/`proxyOnlyEgress` to
`true`**; only a valid signed measurement matching the exact Runtime Assignment
does. Release Gate 3 therefore CLOSES only when Phase 12's real hosted Daytona
Runtime produces the same measured evidence through this exact machinery and
reruns the canary suite unchanged. Until then, production hosted Runtimes
advertise both capabilities `false` because the hermetic harness produces no
measured evidence in production.

### Sign in with Slack (OIDC) identity-link completion

Carried from 8E2 and completed here: a broker `exchange.slack-oidc` operation
verifies the id_token entirely inside the broker (JWKS retrieval through the
broker's injectable exchange client, keys cached with a bounded TTL; `iss`,
`aud`, `exp`, and a `nonce` bound to the Link Challenge digest), returning only
the verified non-secret identity for `verifySlackOidcProof`. The Slack
link-callback route verifies through the broker and completes the Link Challenge
through the connection authority, mirroring the Telegram deep-link discipline.

## Consequences

- A hosted Run exercises a brokered credential only under its exact, current
  Runtime Assignment; supersession revokes eligibility using the existing
  generation fence, and human-session flows are unaffected.
- A hosted capability is advertised only on measured evidence; a misconfigured
  or tampered deploy cannot assert a boundary it does not enforce.
- Slice 8F/8G do not close Gate 3. The closing evidence — a real hosted Runtime
  producing valid measured activation evidence and passing the seeded-canary
  suite through this same machinery — is explicitly a Phase 12 deliverable.
