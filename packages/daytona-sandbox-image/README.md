# TerminalX hardened Daytona Sandbox image

This package builds the immutable Sandbox half of the hosted TerminalX runtime. It is intentionally not a general Daytona image: it runs the pinned Daytona daemon as uid/gid `10001` (`terminalx`) while a root-only supervisor, effect executor, trust pins, and assignment credentials remain behind `/run/terminalx-root` and `/var/lib/terminalx-supervisor`.

The image is useful only with the dedicated hardened Daytona runner at production commit `f9b4dfe428d37f3d956acda4403879516aa8d923`, descended from upstream commit `b5a5d9e78d76c8bcf351f2049620250e0f34eea4`. A generic or unmodified Daytona runner is not an acceptable production boundary.

## Startup and admission

`/usr/local/bin/terminalx-sandbox-init` is a static, argument-free init/supervision process. It requires the container environment to contain exactly `DAYTONA_SANDBOX_ID`, `DAYTONA_SANDBOX_SNAPSHOT`, and `DAYTONA_SANDBOX_USER=terminalx`, and requires the hostname to be the non-identifying literal `terminalx-sandbox`.

The init process:

1. re-measures every fixed executable, trust file, uid, gid, directory, and mode;
2. creates the root-only `0600` Unix listener `/run/terminalx-private/daytona-daemon.sock`, passes only inherited fd 3 to `/usr/local/bin/daytona --terminalx-toolbox-listener-fd=3`, and starts it as `terminalx` with no supplementary groups, empty inheritable/permitted/effective/ambient capability sets, the fixed inherited four-cap bounding mask, and `NoNewPrivs=1`;
3. waits at most five minutes for the root assignment bootstrap to atomically install `/run/terminalx-root/assignment.installed.json`;
4. starts `/usr/local/libexec/terminalx/terminalx-daytona-supervisor /run/terminalx-root /run/terminalx-root/assignment/bootstrap.json` as root;
5. waits for the root-owned `0600` Unix socket and then supervises/reaps both long-lived processes. An unexpected exit terminates the other process and fails the Sandbox.

The supervisor socket deliberately starts before live evidence exists. Admission remains closed until the runner invokes the fixed relay with fresh signed evidence and completes `isolation.attest`; waiting for evidence before creating the socket would deadlock that handshake.

Hardened mode exposes no Daytona TCP process API. The `terminalx` uid cannot traverse `/run/terminalx-private`; only the root supervisor can connect to the listener pathname, while the daemon can accept through its inherited descriptor. The daemon receives only the public fixed `DAYTONA_SANDBOX_ID=terminalx-sandbox`; the real provider UUID and snapshot stay in root process environments. The isolation probe drops to uid `10001` and verifies that every observable agent/PTY environment omits the real Daytona identity variables (the daemon may expose only the fixed literal), treating a non-dumpable daemon environment as unobservable.

## Private-key boundary

No isolation, deployment-binding, observation, state, or effect-enforcer private key is accepted by the image build, copied into a layer, placed in an environment variable, or emitted as a label.

The immutable image contains only these public trust roles:

- bootstrap authority Ed25519 public key;
- isolation-attestation issuer Ed25519 public key;
- effect-manifest authority Ed25519 public key;
- runner deployment-binding Ed25519 public key;
- exact public artifact, executable, source-commit, and Node digests.

The bootstrap, isolation, deployment-binding, and effect-manifest authority keys and key ids must all be distinct. The image pins only the static effect-manifest authority; each assignment carries its own signed manifest and digest bound to its plan, assignment, and derived enforcer identity. Assignment bootstrap installs the matching unique effect-enforcer PKCS#8 key, plus the observation key, as root-owned `0600` files. The supplied effect executable must read only `/run/terminalx-root/assignment/effect-enforcer-provisioning.json` and the fixed `privateKeyFile` it names (`effect-enforcer-key.pk8`). There is no globally pinned per-assignment manifest digest and no permissive fallback executor.

## Fixed runner helpers

All helpers are regular, root-owned, single-link files below the root-only `0500` libexec directory. They expose no shell, path, command, PTY, or caller-selected environment interface.

- `terminalx-assignment-bootstrap` reads one signed assignment envelope and atomically installs assignment-scoped credentials/configuration.
- `terminalx-supervisor-relay` reads fresh signed isolation evidence followed by one framed supervisor request.
- `terminalx-deployment-binding-install` reads at most 256 KiB of canonical signed JSON. It verifies the image-pinned Ed25519 runner key, exact Sandbox id/snapshot, and a fresh TTL no greater than five minutes. A byte-identical replay succeeds. A newer binding may atomically replace the old one only when all claims are identical and `issuedAtMs` increases. Different claims exit `73`; invalid input exits `64`; filesystem/trust failures exit `74`.
- `terminalx-isolation-probe` takes no arguments and emits at most 4096 bytes of canonical public JSON. It rejects missing/ambiguous init, daemon, or supervisor processes; scans every uid-10001 process; validates fixed files/paths; and forks an actual uid-10001 child to prove private-key read/write, root-state/runtime write, and root-process signal denials.

The probe also rejects every unexpected uid-0 process. Concurrent root helpers are accepted only under their fixed Node or native executable path and exact command line, with bounded counts; peer-credential and effect helpers must be direct children of the measured supervisor. Every accepted root process must retain exactly the four-capability `00000000000000e1` envelope and `NoNewPrivs=1`. PID 1 removes supplementary groups, drops every other bounding capability before either long-lived child starts, and fails if the runtime omitted a required capability.

The probe output has this exact recursively key-sorted schema. Capability values are fixed-width lowercase 64-bit hex strings; arrays are sorted by `path`; modes are decimal:

```text
{
  agent: {
    capAmbient, capBounding, capEffective, capInheritable, capPermitted,
    effectiveGid, effectiveUid, filesystemGid, filesystemUid,
    noNewPrivileges, processCount, realGid, realUid, savedGid, savedUid
  },
  daemon: Process,
  denials: {
    agentPrivateKeyReadDenied, agentPrivateKeyWriteDenied,
    agentRootRuntimeWriteDenied, agentRootStateWriteDenied,
    agentSignalInitDenied, agentSignalSupervisorDenied
  },
  executables: [{ gid, mode, nlink, path, regular, uid }],
  init: Process,
  kind: "terminalx.daytona-isolation-probe",
  rootPrivatePaths: [{ gid, mode, nlink, path, type, uid }],
  supervisor: Process,
  version: 1
}
```

`Process` is the same record as `agent` without `processCount` and with `pid`. The probe requires all agent IDs to be `10001`, `CapInh/CapPrm/CapEff/CapAmb=0`, `CapBnd=00000000000000e1` (the fixed CHOWN/KILL/SETGID/SETUID bounding set), and `NoNewPrivs=1`.

## Build inputs

Run:

```bash
packages/daytona-sandbox-image/build-image.sh \
  /absolute/path/to/build-config.json \
  /absolute/new/output-directory
```

The configuration has these exact fields:

```json
{
  "schemaVersion": 1,
  "dockerfileFrontendImage": "docker/dockerfile:1.7@sha256:<64 lowercase hex>",
  "runtimeImage": "registry.example/runtime@sha256:<64 lowercase hex>",
  "toolchainImage": "registry.example/musl-toolchain@sha256:<64 lowercase hex>",
  "platform": "linux/amd64",
  "imageName": "registry.example/terminalx/daytona-sandbox",
  "sourceDateEpoch": 0,
  "supervisorArchiveFile": "/absolute/terminalx-daytona-supervisor.tar.gz",
  "supervisorArtifactDigest": "<archive SHA-256>",
  "daytonaDaemonFile": "/absolute/daytona",
  "daytonaDaemonSha256": "<daemon SHA-256>",
  "effectEnforcerFile": "/absolute/terminalx-effect-enforcer",
  "effectEnforcerSha256": "<effect executable SHA-256>",
  "nodeExecutableSha256": "<regular /usr/local/bin/node SHA-256 in runtimeImage>",
  "bootstrapAuthorityPinFile": "/absolute/bootstrap-authority-pin.json",
  "trust": {
    "isolationIssuerKeyId": "isolation-production-1",
    "isolationIssuerPublicKeySpkiPem": "<canonical Ed25519 public PEM>",
    "hardenedDaytonaSourceCommit": "f9b4dfe428d37f3d956acda4403879516aa8d923",
    "effectManifestAuthorityIssuerKeyId": "effect-manifest-production-1",
    "effectManifestAuthorityPublicKeySpkiPem": "<canonical Ed25519 public PEM>",
    "deploymentBindingIssuerKeyId": "runner-deployment-production-1",
    "deploymentBindingIssuerPublicKeySpkiPem": "<canonical Ed25519 public PEM>"
  }
}
```

The Dockerfile frontend and both base image references are mandatory, mutually distinct, content-addressed references with no floating default. The preparation step embeds the exact frontend digest in the generated Dockerfile and the build also supplies it through BuildKit's `BUILDKIT_SYNTAX` override. The runtime base must already contain a regular root-owned `/usr/local/bin/node`, `/bin/sh`, GNU-compatible account/core utilities, and the desired user toolchain. Its OCI `Config.Env` must be empty: PID 1 admits only the three runner-supplied Daytona variables and constructs each child's environment itself. The Daytona daemon must be ELF; the effect executor may be ELF or use exactly `#!/usr/local/bin/node`. Every supervisor artifact executable must use that exact Node shebang. The build performs no package installation or network access in a `RUN` step. If the exact Daytona daemon, effect executor, Node interpreter, supervisor archive, manifest path/mode/hash, or any public pin is absent or changed, the build fails.

Native helpers are compiled twice from the same prepared sources. The first pinned-toolchain build measures their hashes; the final target depends directly on the same pinned toolchain stage, recompiles them, and refuses the image unless its bytes match those measurements. No host-exported executable is copied into the final image.

The supervisor archive digest becomes `supervisorArtifactDigest`; the archive manifest must name the exact libexec installation paths, pin the root-owned `0555` Node interpreter and per-execution remeasurement contract, and name the same hardened Daytona commit. The release pipeline is responsible for proving that hardened commit descends from the upstream anchor and that the supplied Daytona binary was produced by its signed provenance.

## Reproducible output

The native helper stage and final stage both run with build networking disabled. Buildx emits modern OCI-artifact attestations containing a non-empty SPDX SBOM and maximum-mode SLSA v1 provenance marked reproducible. The verifier requires the pinned frontend, runtime, and toolchain materials; exact build arguments; empty secret/SSH inputs; the hermetic flag; and manifest/subject binding. It also checks all OCI descriptor hashes, final image configuration, required digest labels, and absence of private material before producing:

- `terminalx-daytona-sandbox.oci.tar` — deterministic runnable image layers/config plus build-specific attestations;
- `terminalx-sandbox-image.json` — image manifest/config ids and public labels;
- `buildkit-metadata.json` — BuildKit result metadata;
- `checksums.sha256` — checksums for every release output.

The Docker image id is the release metadata's `imageConfigDigest`. The immutable snapshot/image reference and release artifact digest are intentionally not embedded back into the image, which would create a self-referential digest. The runner supplies those values later in the separately signed deployment binding.

Maximum-mode provenance contains invocation timestamps and identifiers, so the complete attested index is intentionally build-specific even when its runnable image manifest/config are reproducible. Release automation must additionally sign the emitted checksum/index digest with the production release identity; embedded attestations are digest-bound evidence, not an external release signature.
