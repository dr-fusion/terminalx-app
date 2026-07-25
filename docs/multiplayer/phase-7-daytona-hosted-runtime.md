# Phase 7 Daytona hosted Runtime

Status: in progress. Production hosted execution remains unavailable until every acceptance item in
this document is evidenced. LocalTmux remains a development-only Adapter.

## Immutable source baseline

The exact public fork, upstream repository, base ancestry commit, and production fork commit are the
four validated fields in
[`config/daytona-production-source.json`](../../config/daytona-production-source.json). That file is
the only editable release authority for these source values; workflows, builders, artifacts,
runtime admission, and image trust inputs derive from or compare against it.

- Immutable reference: `terminalx-v1-base-b5a5d9e`

The base fork's `main` reference and peeled immutable tag resolved to the reviewed ancestry commit.
The two removed fork commits were `b40f732a38a9bdb5a124312bbe4b32712836c7dc` and
`ec4c21b2d597091ac09ecc278f3bcc172575a987`. Builds and deployments must verify the full commit,
artifact digests, and signed provenance; neither a branch nor a tag is sufficient evidence. The
base commit is privileged for ordinary non-GPU Sandboxes and has no PID limit, so it must never be
attested as the isolated production Runtime. SDK, runner, image, and supervisor evidence must all
name the canonical `productionForkCommit`.
The release workflow, application activation gate, image trust pins, supervisor artifact, and
control-plane settings reject every other commit.

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

`scripts/build-pinned-daytona-runtime.sh` applies the same source and ancestry checks, then builds
the linux/amd64 runner and daemon twice with separate fresh Go build caches, `-buildvcs=true`, and
`-trimpath`. Both binaries must be byte-identical across rebuilds and must independently report the
canonical clean fork commit. The fork-owned generator emits the exact canonical
`terminalx.daytona-hardened-runtime-artifacts` manifest; the image builder derives its daemon and
runner pins only from that manifest and verifies the daemon bytes before building.
The builder requires a standalone checkout with a real `.git` directory: linked worktrees are
rejected before compilation because Go does not reliably emit the VCS settings required by the
runtime identity contract from a `.git` indirection file.

The runtime release directory contains raw measured subjects and a deterministic
`terminalx-daytona-runtime-<commit-prefix>.tar.gz`. GitHub workflow-artifact downloads normalize raw
file permissions, so only the tar archive is the mode-preserving handoff to the Sandbox image build.
Before extraction, verify the tar subject with `gh attestation verify` against this repository, then
run `scripts/verify-daytona-runtime-release-archive.sh` with the downloaded archive, downloaded
`checksums.sha256`, and a new absolute output directory. The verifier binds the tar digest to the
release checksums, admits exactly the runner, daemon, runtime manifest, and internal checksum file,
checks all bytes, and restores/rechecks `0555` executable and `0444` manifest/checksum modes. Image
build configuration may reference only those verified extracted files.

SDK determinism uses two independent exact fork checkouts with the Nx daemon and local/remote Nx
cache bypassed. Runtime determinism also uses those independent checkouts in addition to the two
fresh Go build caches inside each runtime build.

Production activation accepts only the signed deployment-manifest v2 trust domain. Its closed
artifact set binds the SDK, supervisor, complete runtime-artifact manifest, runner binary, daemon
binary, SBOM, and provenance by distinct lowercase SHA-256 values. The measured deployment inputs,
provider runner configuration, image labels, root-owned image trust pins, signed bootstrap, and
live runner isolation claim must agree with those values. Legacy v1 deployment manifests fail
closed rather than being upgraded implicitly.

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

1. Verify the signed v2 deployment manifest, exact fork ancestry, SDK, supervisor, runtime
   manifest, runner, daemon, SBOM, provenance, the snapshot UUID-to-reference mapping,
   independently inspected image ID, supervisor identity, and effective isolation profile.
2. Load the complete signed Runtime trust group from an explicit operator-owned private root.
3. Open the Team Session kernel and reconstruct exact durable hosted assignment plans.
4. Construct the hosted Adapter and portable `RuntimeSupervisorRoot`.
5. Await the root startup barrier and require readiness before admitting any hosted transport.
6. On shutdown, withdraw availability, close ingress, stop the root, dispose provider streams and
   clients, zero credential buffers, and close the Team Session kernel last.

## Production activation and private configuration

Hosted production has one selector: `TERMINALX_HOSTED_RUNTIME=daytona`. Absence means disabled and
dormant hosted paths are not read. An empty value, `true`, `false`, or a differently cased selector
is invalid; once selected, every unsupported `TERMINALX_HOSTED_*` variable is also rejected.
Activation additionally requires `NODE_ENV=production` and the existing canonical transport gate
`TERMINALX_MULTIPLAYER_ENABLED=true`. The selector is installed before multiplayer service
selection and before the HTTP server listens. An enabled deployment with a missing setting,
unavailable file, incomplete composer, or failed Runtime graph exits through the generic startup
failure and never falls back to LocalTmux.

These are the complete accepted `TERMINALX_HOSTED_*` environment variables. Values other than the
selector are absolute canonical paths; secret bytes are never accepted from the environment.

| Variable                                                            | File contract                                                          |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `TERMINALX_HOSTED_RUNTIME`                                          | Exact literal `daytona`; the only hosted enable selector.              |
| `TERMINALX_HOSTED_TRUST_ROOT`                                       | Absolute canonical operator-owned configuration directory.             |
| `TERMINALX_HOSTED_RUNTIME_CONFIG_FILE`                              | Canonical public configuration JSON plus exactly one LF.               |
| `TERMINALX_HOSTED_DAYTONA_API_CREDENTIAL_FILE`                      | 1–8192 raw visible-ASCII bytes, no whitespace or trailing LF.          |
| `TERMINALX_HOSTED_RUNNER_CREDENTIAL_FILE`                           | Distinct 1–8192 raw visible-ASCII bytes, no whitespace or trailing LF. |
| `TERMINALX_HOSTED_ASSIGNMENT_MASTER_KEY_FILE`                       | Exactly 32 nonzero raw bytes.                                          |
| `TERMINALX_HOSTED_BOOTSTRAP_AUTHORITY_PRIVATE_KEY_FILE`             | Canonical unencrypted Ed25519 PKCS8 PEM matching its public pin.       |
| `TERMINALX_HOSTED_TEAM_COMMAND_AUTHORITY_PRIVATE_KEY_FILE`          | Distinct canonical unencrypted Ed25519 PKCS8 PEM matching its pin.     |
| `TERMINALX_HOSTED_PLATFORM_COMPENSATION_AUTHORITY_PRIVATE_KEY_FILE` | Distinct canonical unencrypted Ed25519 PKCS8 PEM matching its pin.     |
| `TERMINALX_HOSTED_OPAQUE_HANDLE_KEY_FILE`                           | 32–64 nonzero raw bytes, distinct from every other private value.      |

The trust root and every directory below it must be owned by the process effective UID with mode
`0500` or `0700`. Every file must be a no-follow regular file owned by that UID, have exactly one
link, and use mode `0400` or `0600`. All paths, metadata, inode identity, timestamps, and sizes are
checked before and after a bounded descriptor read. Symlinks, hard links, accessors, relative or
noncanonical paths, replacement races, permissive parents, and unsupported `TERMINALX_HOSTED_*`
variables fail closed.

The public configuration file has the exact top-level fields `version`, `kind`, `identities`, and
`settings`; it uses the bounded Runtime canonical-JSON profile and exactly one trailing LF:

```json
{
  "identities": {
    "bootstrapAuthority": { "keyId": "…", "publicKeySpkiPem": "…" },
    "platformCompensationAuthority": { "keyId": "…", "publicKeySpkiPem": "…" },
    "teamCommandAuthority": { "keyId": "…", "publicKeySpkiPem": "…" }
  },
  "kind": "terminalx.daytona-hosted-runtime-configuration",
  "settings": {},
  "version": 1
}
```

The rendered example is structural; operators must generate canonical bytes rather than copying
the ellipses. Each SPKI must be canonical Ed25519 PEM and match its role's exact canonical,
unencrypted PKCS8 PEM, including its final LF. Key IDs, SPKI digests, file paths, and all private
byte values must be unique across roles. The loader holds private bytes in a one-shot lease: the
concrete composer must transfer them into their owning constructors, after which every source
buffer is zeroed on success, rejection, or disposal.

There is intentionally no effect-manifest private-key variable. The concrete production composer
derives assignment-scoped effect identities, persists the exact provider/plan/policy/manifest/set
binding, routes verification through the matching trust set, and transfers each private owner into
the root graph before availability. The pinned image exposes the real four-operation PTY protocol
over its root-private Unix socket; ambiguous create results reconcile by exact terminal identity
before one bounded retry. `TERMINALX_HOSTED_RUNTIME=daytona` still fails before listen on any
missing trust input, invalid production pin, incomplete owner transfer, or root-readiness failure.

An ordinary apply may initiate an effect only after the durable dispatch interlock. Reconciliation
observes first and never blindly repeats a create or destructive operation. Zero, one, or multiple
exact binding matches mean create only while still desired, validate the one exact match, or fail
closed and quarantine. A timeout or abort after dispatch is an ambiguous outcome and retains the
same idempotency identity until observation resolves it.

## Per-assignment observation credentials and recovery

Every hosted Runtime Assignment has a fresh Ed25519 observation identity. The durable assignment
plan and Runtime observation-key registry contain only an opaque `keyProvisioningRef`, issuer key
ID, and canonical public SPKI. The private key must remain in the distinct root-owned supervisor
boundary: it must never enter Team Session SQLite, an outbox payload, the Daytona agent process or
environment, a provider request, a terminal stream, a log, or a public projection. The supervisor
resolves the opaque reference from a root-owned provisioning record, verifies the complete Runtime
binding and public/private key match, and returns signing capabilities rather than private bytes.
Assignment creation and readiness fail closed if any part of that resolution cannot be proven.

Assignee-loss recovery never relabels or resumes the fenced Sandbox. After the exact fence receipt,
an assignee claim advances the Runtime authorization generation, creates a new immutable assignment
plan with a fresh Sandbox generation and observation identity, and durably queues two independently
retryable effects: ensure the replacement and retire the exact old binding. The Session remains
authorization-pending and the Run remains paused on its historical binding until the replacement's
ensure receipt atomically installs a new immutable Run policy revision and rebinds the Run. The old
retire effect stays pinned to its original plan and binding, so it remains safe if it arrives before
ensure, after resume, after restart, or after a later authorization generation. A terminal ensure
failure quarantines the replacement and Session rather than making either Runtime available.

The root-private resolver is necessary but not sufficient production evidence. The pinned Daytona
image/init path must install and start the supervisor as a separate root-only process and transport
its provisioning record through a root-owned file or socket that the Daytona daemon and agent user
cannot read. Until that image and transport pass the real-provider isolation suite, hosted
production admission remains disabled.

## Isolation profile for this phase

Every hosted Session receives one non-public, dedicated Sandbox with:

- one deployment-attested Daytona snapshot UUID that resolves to an exact preloaded digest
  reference and an independently pinned Docker-inspected image ID; build-based image artifacts are
  rejected;
- a non-root per-Sandbox identity and distinct filesystem/process namespace;
- no host, shared writable, Docker, container-runtime, or cross-Session mounts;
- finite CPU, memory, disk, process, and provider ceilings;
- all direct outbound network blocked for Phase 7; and
- a pinned TerminalX supervisor that returns signed, replayable receipts and effective enforcement
  attestations.

The runner consumes both standard `Authorization` and `X-Daytona-Authorization` credentials before
toolbox proxying. Neither header, the runner-wide API token, nor any provider credential may reach
the non-root Daytona daemon, agent, supervisor protocol, terminal stream, or observation output.

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
- **7D — production composition and artifacts:** exact-commit SDK/supervisor/runner/daemon build,
  signed v2 deployment manifest, SBOM and provenance attestations, strict private configuration,
  server wiring, probes, and shutdown.
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
