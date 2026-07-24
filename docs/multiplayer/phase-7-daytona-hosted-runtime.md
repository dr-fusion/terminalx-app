# Phase 7 Daytona hosted Runtime

Status: in progress. Production hosted execution remains unavailable until every acceptance item in
this document is evidenced. LocalTmux remains a development-only Adapter.

## Immutable source baseline

- Public fork: `https://github.com/procyon-labs-io/daytona`
- Required fork commit: `b5a5d9e78d76c8bcf351f2049620250e0f34eea4`
- Immutable reference: `terminalx-v1-base-b5a5d9e`
- Verified upstream: `https://github.com/daytonaio/daytona`
- Verified upstream base: `b5a5d9e78d76c8bcf351f2049620250e0f34eea4`

The fork's `main` reference and the peeled immutable tag both resolve to the required full commit.
The two removed fork commits were `b40f732a38a9bdb5a124312bbe4b32712836c7dc` and
`ec4c21b2d597091ac09ecc278f3bcc172575a987`. Builds and deployments must verify the full commit,
artifact digests, and signed provenance; neither a branch nor a tag is sufficient evidence.

The Daytona server repository is AGPL-3.0. The TypeScript SDK and generated TypeScript clients are
Apache-2.0. TerminalX does not copy Daytona server code into its MIT repository. Any deployed fork
modification remains public and follows the applicable source-availability obligations.

`scripts/build-pinned-daytona-sdk.sh` accepts only a clean checkout whose origin and `HEAD` match
the production source pin. It builds the SDK and both generated client dependencies directly from
that checkout, emits a deterministic bundle and component checksums, and records the source and
build command in the bundle. The release workflow generates an SPDX 2.3 SBOM, creates GitHub
artifact provenance using OIDC, and uploads the complete release inputs. The workflow artifacts
still require the separately pinned release-authority signature represented by the deployment
manifest below; CI provenance does not grant production activation by itself.

## Module shape

The production server uses one deep hosted-multiplayer Module. Its small interface starts a fully
verified graph, reports readiness, admits hosted transports, and closes the graph in the only safe
order. Daytona provider operations live behind a private control-plane port with a deterministic
in-memory Adapter for interface tests.

The hosted Adapter exposes only frozen projections required by the portable Runtime supervisors:

- assignment apply/reconcile;
- signed command dispatch;
- signed receipt follow; and
- exact lifecycle, follow, and compensation handle resolution.

Provider Sandbox, process, PTY, command, organization, target, and credential identifiers never
cross that seam. A `RuntimeHandle.opaqueHandleRef` is a TerminalX-generated keyed reference bound to
the complete Runtime Assignment and Sandbox generations; it is never a provider identifier.

## Required ordering and reconciliation

1. Verify the signed deployment manifest, exact fork ancestry, artifacts, SBOM, provenance, image
   or snapshot digest, supervisor identity, and effective isolation profile.
2. Load the complete signed Runtime trust group from an explicit operator-owned private root.
3. Open the Team Session kernel and reconstruct exact durable hosted assignment plans.
4. Construct the hosted Adapter and portable `RuntimeSupervisorRoot`.
5. Await the root startup barrier and require readiness before admitting any hosted transport.
6. On shutdown, withdraw availability, close ingress, stop the root, dispose provider streams and
   clients, zero credential buffers, and close the Team Session kernel last.

An ordinary apply may initiate an effect only after the durable dispatch interlock. Reconciliation
observes first and never blindly repeats a create or destructive operation. Zero, one, or multiple
exact binding matches mean create only while still desired, validate the one exact match, or fail
closed and quarantine. A timeout or abort after dispatch is an ambiguous outcome and retains the
same idempotency identity until observation resolves it.

## Isolation profile for this phase

Every hosted Session receives one non-public, dedicated Sandbox with:

- an immutable image or snapshot digest;
- a non-root per-Sandbox identity and distinct filesystem/process namespace;
- no host, shared writable, Docker, container-runtime, or cross-Session mounts;
- finite CPU, memory, disk, process, and provider ceilings;
- outbound network blocked by default, with only signed exact allow-list configuration; and
- a pinned TerminalX supervisor that returns signed, replayable receipts and effective enforcement
  attestations.

Requested configuration is not proof of enforcement. Readiness requires the deployed supervisor
and every relevant effect enforcer to attest the exact binding, authorization generation, policy
digests, and isolation profile.

Phase 7 intentionally advertises `brokeredCredentials: false`, `proxyOnlyEgress: false`, and
`yoloEligible: false`. Phase 8 must prove brokered secret and proxy-only egress guarantees, and Phase
9 must prove approval, accounting, and one-use YOLO challenge guarantees before those capabilities
can become true.

## Implementation slices

- **7A — hosted model and deterministic vertical boot:** exact source/deployment manifest,
  provider-neutral control-plane port, in-memory Adapter, durable hosted assignment plan, real
  SQLite kernel, full root readiness, and ordered shutdown.
- **7B — exact Daytona control plane:** cancellable lower-level client, private identifier vault,
  ensure/follow/pause/resume/stop/fence/retire mappings, and timeout reconciliation.
- **7C — signed supervisor and terminal transport:** command idempotency, signed receipt cursor,
  provider-neutral terminal connector, reconnect, resize, input fencing, and readiness loss.
- **7D — production composition and artifacts:** exact-commit SDK/supervisor build, SBOM and
  provenance attestations, strict private configuration, server wiring, probes, and shutdown.
- **7E — hosted isolation evidence:** real-provider restart, duplicate-create, stale replacement,
  escape, network, namespace, resource, retirement, and destructive-race tests.

## Phase acceptance

Phase 7 completes only when:

- no production path can fall back from Daytona to LocalTmux;
- the server remains unavailable on any source, artifact, trust, deployment-attestation, bootstrap,
  reconciliation, or readiness failure;
- stale ensure or retire work cannot resurrect or delete a replacement Sandbox;
- signed command/receipt semantics pass against the real pinned fork through restart and ambiguous
  provider outcomes;
- provider identifiers and credentials are absent from public state, errors, events, logs, traces,
  and opaque handles; and
- isolation tests demonstrate filesystem, process, identity, network, resource, and cleanup
  enforcement for mutually untrusted Sessions.

Passing Phase 7 closes the hosted evidence portion of Runtime truth and hosted isolation (release
Gates 1 and 2). It does not close brokered secrets, approvals, limits, YOLO, retained evidence, or
production operations assigned to later phases.
