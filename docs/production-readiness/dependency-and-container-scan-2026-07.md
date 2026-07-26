# Dependency & container scan — 2026-07-26 (Phase 12)

## Dependency vulnerability scan (`npm audit`) — RUN, real output

Command output captured on the Phase 12 branch (`agent/phase12-verification-release`):

| Scan                   | critical | high | moderate | low | info | total |
| ---------------------- | -------: | ---: | -------: | --: | ---: | ----: |
| `npm audit` (all deps) |        0 |    0 |        0 |   0 |    0 |     0 |
| `npm audit --omit=dev` |        0 |    0 |        0 |   0 |    0 |     0 |

`npm audit` → **`found 0 vulnerabilities`**. Runtime (prod-only) tree is also clean.

There are **no P0/P1 (critical/high) dependency findings**, and no moderate/low advisories
either — nothing to remediate. This is consistent with the tight version pins in `package.json`
and the `overrides` block (`postcss 8.5.23`, `hono >=4.12.27`, `@hono/node-server >=2.0.5`,
`sharp 0.35.3`). CI already gates on `npm audit --omit=dev --audit-level=high` (`.github/workflows/ci.yml`).

### Vendored / `file:` dependencies (not covered by the advisory database)

`@wterm/*` (vendored tarballs under `vendor/wterm/`) and other `file:` deps are not in the npm
advisory database, so `npm audit` cannot assess them. They are first-party/vendored and pinned by
content; they are covered by the SBOM (below) as `NOASSERTION` download locations and should be
reviewed on each vendor bump. No known advisories apply.

## SBOM coverage (Phase 12 addition)

`scripts/generate-sbom.mjs` emits SPDX 2.3 JSON SBOMs (self-contained; walks `package-lock.json`,
no external tooling required) for:

- `terminalx-app` (root) — **820 resolved dependency packages**
- `@terminalx/daytona-supervisor`
- `@terminalx/secret-broker`

plus a `checksums.sha256` over all three. This closes the prior gap where the secret-broker package
had no SBOM step. The `daytona-sandbox-image` OCI package has no npm manifest; its SBOM must come
from the image build (BuildKit `sbom:true` / anchore against the built image) — see the container
section.

## Container scan — tooling status (this environment)

Container image vulnerability scanning tooling is **not available in this environment**:

| Tool      | Status |
| --------- | ------ |
| cosign    | absent |
| syft      | absent |
| cyclonedx | absent |
| trivy     | absent |
| grype     | absent |
| docker    | absent |

Consequences and the honest boundary:

- **Container image build + scan cannot be executed here** (no docker/BuildKit, no trivy/grype).
- The CI docker-build job (`.github/workflows/ci.yml`) already produces a BuildKit-native SBOM
  (`sbom: true`) and provenance (`provenance: mode=max`) for the **app image**, but there is
  **currently no image vulnerability scan step** (trivy/grype) in CI — a genuine gap.

### Recommended container-scan step (to add in CI, pinned action)

Add an image vulnerability scan after the docker build, failing on HIGH/CRITICAL:

```yaml
- uses: aquasecurity/trivy-action@<pinned-sha> # or anchore/grype
  with:
    image-ref: ${{ steps.build.outputs.image }}
    severity: HIGH,CRITICAL
    exit-code: "1"
    ignore-unfixed: true
```

This must run against a **real built image** in CI; it cannot be exercised in this sandbox.

## Summary

- Dependency scan: **RUN, 0 findings, no P0/P1** (evidence above).
- SBOM: generated for app + supervisor + secret-broker (SPDX 2.3 + checksums), reproducible via
  `scripts/generate-sbom.mjs`.
- Container image scan: **documentation-only here** (no docker/trivy/grype); the itemized CI step
  above must run on a real image before the production multiplayer profile is enabled.
