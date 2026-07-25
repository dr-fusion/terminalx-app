import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
import productionSourceConfiguration from "../../config/daytona-production-source.json";
import { validateDaytonaProductionSourceConfiguration } from "@/lib/runtime/daytona-production-source";
import {
  DAYTONA_DEPLOYMENT_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN,
  DAYTONA_FORK_REPOSITORY,
  DAYTONA_PRODUCTION_FORK_COMMIT,
  DAYTONA_UPSTREAM_BASE_COMMIT,
  DAYTONA_UPSTREAM_REPOSITORY,
  DaytonaDeploymentArtifactError,
  digestDaytonaDeploymentArtifactManifestClaims,
  resolveDaytonaSourcePin,
  verifyDaytonaDeploymentArtifacts,
  type DaytonaDeploymentArtifactErrorCode,
  type DaytonaDeploymentArtifactManifest,
  type DaytonaDeploymentArtifactManifestClaims,
  type DaytonaDeploymentManifestSignatureVerifier,
  type DaytonaImmutableSandboxArtifact,
  type DaytonaSourceEnvironment,
} from "@/lib/runtime/daytona-source";

const DIGESTS = Object.freeze({
  sdk: "1".repeat(64),
  supervisor: "2".repeat(64),
  runtimeArtifactManifest: "8".repeat(64),
  runner: "9".repeat(64),
  daemon: "a".repeat(64),
  sbom: "3".repeat(64),
  provenance: "4".repeat(64),
  sandbox: "5".repeat(64),
  isolation: "6".repeat(64),
  snapshot: "7".repeat(64),
});
const SIGNATURE = Buffer.alloc(64, 9).toString("base64url");
const SNAPSHOT_ID = "123e4567-e89b-42d3-a456-426614174000";
const SNAPSHOT_REF = `registry.example.com/terminalx/sandbox@sha256:${DIGESTS.snapshot}`;
const SNAPSHOT_IMAGE_ID = `sha256:${"8".repeat(64)}`;
const SOURCE_ENVIRONMENT: DaytonaSourceEnvironment = Object.freeze({
  TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_FORK_REPOSITORY,
  TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT,
});

describe("Daytona production source pin", () => {
  it("loads every runtime source field from the exact canonical JSON schema", () => {
    expect(Object.keys(productionSourceConfiguration)).toEqual([
      "schemaVersion",
      "kind",
      "forkRepository",
      "productionForkCommit",
      "upstreamRepository",
      "upstreamBaseCommit",
    ]);
    expect(productionSourceConfiguration.schemaVersion).toBe(1);
    expect(productionSourceConfiguration.kind).toBe("terminalx.daytona-production-source");
    expect(DAYTONA_FORK_REPOSITORY).toBe(productionSourceConfiguration.forkRepository);
    expect(DAYTONA_PRODUCTION_FORK_COMMIT).toBe(productionSourceConfiguration.productionForkCommit);
    expect(DAYTONA_UPSTREAM_REPOSITORY).toBe(productionSourceConfiguration.upstreamRepository);
    expect(DAYTONA_UPSTREAM_BASE_COMMIT).toBe(productionSourceConfiguration.upstreamBaseCommit);
    expect(DAYTONA_PRODUCTION_FORK_COMMIT).not.toBe(DAYTONA_UPSTREAM_BASE_COMMIT);
  });

  it("exports the canonical source semantically to shell and workflow consumers", () => {
    const reader = resolve(process.cwd(), "scripts/read-daytona-production-source.mjs");
    const json = spawnSync(process.execPath, [reader, "json"], { encoding: "utf8" });
    expect(json.status, json.stderr).toBe(0);
    expect(JSON.parse(json.stdout)).toEqual(productionSourceConfiguration);

    const outputs = spawnSync(process.execPath, [reader, "github-output"], {
      encoding: "utf8",
    });
    expect(outputs.status, outputs.stderr).toBe(0);
    expect(
      Object.fromEntries(
        outputs.stdout
          .trim()
          .split("\n")
          .map((line) => line.split("="))
      )
    ).toEqual({
      fork_repository: new URL(productionSourceConfiguration.forkRepository).pathname.slice(1),
      fork_repository_url: productionSourceConfiguration.forkRepository,
      production_fork_commit: productionSourceConfiguration.productionForkCommit,
      upstream_repository_url: productionSourceConfiguration.upstreamRepository,
      upstream_base_commit: productionSourceConfiguration.upstreamBaseCommit,
    });

    const workflow = readFileSync(
      resolve(process.cwd(), ".github/workflows/daytona-sdk-artifact.yml"),
      "utf8"
    );
    expect(workflow).toContain("node scripts/read-daytona-production-source.mjs github-output");
    expect(workflow).toContain("steps.daytona-source.outputs.production_fork_commit");
    expect(workflow).toContain("steps.daytona-source.outputs.upstream_base_commit");
  });

  it("rejects malformed, floating, aliased, and extended canonical configurations", async () => {
    const helper = (await import(
      pathToFileURL(resolve(process.cwd(), "scripts/lib/daytona-production-source.mjs")).href
    )) as {
      validateDaytonaProductionSource(value: unknown): unknown;
    };
    const invalid = [
      { ...productionSourceConfiguration, extra: true },
      { ...productionSourceConfiguration, productionForkCommit: "main" },
      {
        ...productionSourceConfiguration,
        productionForkCommit: productionSourceConfiguration.upstreamBaseCommit,
      },
      {
        ...productionSourceConfiguration,
        upstreamRepository: productionSourceConfiguration.forkRepository,
      },
      { ...productionSourceConfiguration, forkRepository: "git@github.com:example/daytona.git" },
    ];
    for (const value of invalid) {
      expect(() => helper.validateDaytonaProductionSource(value)).toThrow(TypeError);
      expect(() => validateDaytonaProductionSourceConfiguration(value)).toThrow(TypeError);
    }

    let getterInvoked = false;
    const accessor = Object.defineProperty(
      { ...productionSourceConfiguration },
      "productionForkCommit",
      {
        enumerable: true,
        get() {
          getterInvoked = true;
          return productionSourceConfiguration.productionForkCommit;
        },
      }
    );
    expect(() => helper.validateDaytonaProductionSource(accessor)).toThrow(TypeError);
    expect(() => validateDaytonaProductionSourceConfiguration(accessor)).toThrow(TypeError);
    expect(getterInvoked).toBe(false);

    let proxyTrapInvoked = false;
    const proxy = new Proxy(productionSourceConfiguration, {
      ownKeys() {
        proxyTrapInvoked = true;
        return [];
      },
    });
    expect(() => helper.validateDaytonaProductionSource(proxy)).toThrow(TypeError);
    expect(() => validateDaytonaProductionSourceConfiguration(proxy)).toThrow(TypeError);
    expect(proxyTrapInvoked).toBe(false);
  });

  it("writes SDK and supervisor artifact source records from the canonical config", () => {
    const root = mkdtempSync(join(tmpdir(), "terminalx-daytona-source-artifacts-"));
    try {
      const archives = [
        "daytona-api-client-0.0.0-dev.tgz",
        "daytona-sdk-0.0.0-dev.tgz",
        "daytona-toolbox-api-client-0.0.0-dev.tgz",
      ].map((name, index) => {
        const path = join(root, name);
        writeFileSync(path, `archive-${index}`);
        return path;
      });
      const sdkOutput = join(root, "daytona-sdk-artifact.json");
      const sdk = spawnSync(
        process.execPath,
        [resolve(process.cwd(), "scripts/write-daytona-sdk-artifact.mjs"), sdkOutput, ...archives],
        { encoding: "utf8" }
      );
      expect(sdk.status, sdk.stderr).toBe(0);
      expect(JSON.parse(readFileSync(sdkOutput, "utf8")).source).toEqual({
        repository: productionSourceConfiguration.forkRepository,
        productionCommit: productionSourceConfiguration.productionForkCommit,
        upstreamBaseCommit: productionSourceConfiguration.upstreamBaseCommit,
      });

      const artifactRoot = join(root, "supervisor");
      mkdirSync(join(artifactRoot, "bin"), { recursive: true });
      for (const name of [
        "terminalx-daytona-supervisor",
        "terminalx-supervisor-relay",
        "terminalx-assignment-bootstrap",
      ]) {
        const path = join(artifactRoot, "bin", name);
        writeFileSync(path, `executable-${name}`);
        chmodSync(path, 0o555);
      }
      const supervisorOutput = join(root, "daytona-supervisor-artifact.json");
      const terminalxCommit = "1".repeat(40);
      const supervisor = spawnSync(
        process.execPath,
        [
          resolve(process.cwd(), "scripts/write-daytona-supervisor-artifact.mjs"),
          supervisorOutput,
          artifactRoot,
          terminalxCommit,
          productionSourceConfiguration.productionForkCommit,
        ],
        { encoding: "utf8" }
      );
      expect(supervisor.status, supervisor.stderr).toBe(0);
      expect(JSON.parse(readFileSync(supervisorOutput, "utf8")).source).toEqual({
        terminalxCommit,
        daytonaProductionCommit: productionSourceConfiguration.productionForkCommit,
        daytonaUpstreamBaseCommit: productionSourceConfiguration.upstreamBaseCommit,
      });
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  it("does not duplicate active commit values across release consumers", () => {
    for (const relativePath of [
      ".github/workflows/daytona-sdk-artifact.yml",
      "scripts/build-pinned-daytona-sdk.sh",
      "scripts/build-pinned-daytona-runtime.sh",
      "scripts/build-pinned-daytona-supervisor.sh",
      "scripts/verify-daytona-runtime-release-archive.sh",
      "scripts/write-daytona-sdk-artifact.mjs",
      "scripts/write-daytona-supervisor-artifact.mjs",
      "packages/daytona-sandbox-image/scripts/prepare-build-context.mjs",
      "packages/daytona-sandbox-image/scripts/write-static-pins.mjs",
      "packages/daytona-supervisor/src/effective-isolation.ts",
      "src/lib/runtime/daytona-production-source.ts",
    ]) {
      const source = readFileSync(resolve(process.cwd(), relativePath), "utf8");
      expect(source, relativePath).not.toContain(DAYTONA_PRODUCTION_FORK_COMMIT);
      expect(source, relativePath).not.toContain(DAYTONA_UPSTREAM_BASE_COMMIT);
    }
  });

  it("keeps optional development composition disabled when neither pin is present", () => {
    expect(resolveDaytonaSourcePin({})).toBeNull();
    expect(
      resolveDaytonaSourcePin({
        TERMINALX_DAYTONA_FORK_REPOSITORY: undefined,
        TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: undefined,
      })
    ).toBeNull();
  });

  it("accepts only the exact production fork and accepted upstream base", () => {
    const pin = resolveDaytonaSourcePin(SOURCE_ENVIRONMENT);
    expect(pin).toEqual({
      forkRepository: DAYTONA_FORK_REPOSITORY,
      forkCommit: DAYTONA_PRODUCTION_FORK_COMMIT,
      upstreamRepository: DAYTONA_UPSTREAM_REPOSITORY,
      upstreamBaseCommit: DAYTONA_UPSTREAM_BASE_COMMIT,
    });
    expect(Object.isFrozen(pin)).toBe(true);
  });

  it.each([
    { TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_FORK_REPOSITORY },
    { TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: "https://github.com/example/daytona",
      TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT,
    },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_UPSTREAM_REPOSITORY,
      TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT,
    },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: `${DAYTONA_FORK_REPOSITORY}.git`,
      TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT,
    },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: ` ${DAYTONA_FORK_REPOSITORY}`,
      TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT,
    },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_FORK_REPOSITORY,
      TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: "main",
    },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_FORK_REPOSITORY,
      TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: "0".repeat(40),
    },
    {
      TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_FORK_REPOSITORY,
      TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT.toUpperCase(),
    },
  ])("rejects absent, floating, normalized, or merely well-formed alternatives", (environment) => {
    expectErrorCode(() => resolveDaytonaSourcePin(environment), "invalid_source_pin");
  });

  it("rejects extra fields, accessors, and proxies without invoking hostile traps", () => {
    expectErrorCode(
      () =>
        resolveDaytonaSourcePin({
          ...SOURCE_ENVIRONMENT,
          extra: "not-production-data",
        } as DaytonaSourceEnvironment),
      "invalid_source_pin"
    );

    let getterInvoked = false;
    const accessor = Object.defineProperty({}, "TERMINALX_DAYTONA_FORK_REPOSITORY", {
      enumerable: true,
      get() {
        getterInvoked = true;
        return DAYTONA_FORK_REPOSITORY;
      },
    });
    expectErrorCode(
      () => resolveDaytonaSourcePin(accessor as DaytonaSourceEnvironment),
      "invalid_source_pin"
    );
    expect(getterInvoked).toBe(false);

    let proxyTrapInvoked = false;
    const proxy = new Proxy(SOURCE_ENVIRONMENT, {
      ownKeys() {
        proxyTrapInvoked = true;
        return [];
      },
    });
    expectErrorCode(() => resolveDaytonaSourcePin(proxy), "invalid_source_pin");
    expect(proxyTrapInvoked).toBe(false);
  });
});

describe("Daytona deployment artifact manifest", () => {
  it("verifies and deeply snapshots an exact signed OCI deployment manifest", () => {
    const manifest = signedManifest();
    const signatureVerifier = vi.fn<DaytonaDeploymentManifestSignatureVerifier>(() => true);
    const fetch = vi.fn(() => {
      throw new Error("network access is forbidden");
    });
    vi.stubGlobal("fetch", fetch);
    try {
      const verified = verifyDaytonaDeploymentArtifacts({
        sourceEnvironment: SOURCE_ENVIRONMENT,
        manifest,
        signatureVerifier,
      });
      const claimsDigest = digestDaytonaDeploymentArtifactManifestClaims(manifestClaims());

      expect(verified.sourcePin).toEqual(manifest.source);
      expect(verified.manifestDigest).toBe(claimsDigest);
      expect(verified.manifest).toEqual(manifest);
      expect(signatureVerifier).toHaveBeenCalledTimes(1);
      expect(signatureVerifier).toHaveBeenCalledWith({
        algorithm: "ed25519",
        issuerKeyId: "terminalx-release:daytona-production:v2",
        claimsDigest,
        canonicalPayload: expect.stringMatching(
          new RegExp(`^${escapeRegExp(DAYTONA_DEPLOYMENT_MANIFEST_AUTHORITY_SIGNATURE_DOMAIN)}`)
        ),
        signature: SIGNATURE,
      });
      const verification = signatureVerifier.mock.calls[0]?.[0];
      expect(verification?.canonicalPayload).toContain(claimsDigest);
      expect(verification?.canonicalPayload).not.toContain(SIGNATURE);
      expect(Object.isFrozen(verification)).toBe(true);
      expect(Object.isFrozen(verified)).toBe(true);
      expect(Object.isFrozen(verified.sourcePin)).toBe(true);
      expect(Object.isFrozen(verified.manifest)).toBe(true);
      expect(Object.isFrozen(verified.manifest.source)).toBe(true);
      expect(Object.isFrozen(verified.manifest.artifacts)).toBe(true);
      expect(Object.isFrozen(verified.manifest.artifacts.sdk)).toBe(true);
      expect(Object.isFrozen(verified.manifest.artifacts.runtimeArtifactManifest)).toBe(true);
      expect(Object.isFrozen(verified.manifest.artifacts.runner)).toBe(true);
      expect(Object.isFrozen(verified.manifest.artifacts.daemon)).toBe(true);
      expect(Object.isFrozen(verified.manifest.sandboxArtifact)).toBe(true);
      expect(Object.isFrozen(verified.manifest.isolationProfile)).toBe(true);
      expect(Object.isFrozen(verified.manifest.authority)).toBe(true);
      expect(fetch).not.toHaveBeenCalled();

      const mutableManifest = manifest as unknown as {
        artifacts: { sdk: { sha256: string } };
      };
      mutableManifest.artifacts.sdk.sha256 = "f".repeat(64);
      expect(verified.manifest.artifacts.sdk.sha256).toBe(DIGESTS.sdk);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("accepts a content-digested immutable Daytona snapshot alternative", () => {
    const sandboxArtifact: DaytonaImmutableSandboxArtifact = {
      kind: "daytona-snapshot",
      snapshotId: SNAPSHOT_ID,
      snapshotRef: SNAPSHOT_REF,
      imageId: SNAPSHOT_IMAGE_ID,
      sha256: DIGESTS.snapshot,
    };
    const manifest = signedManifest(manifestClaims(sandboxArtifact));
    expect(
      verifyDaytonaDeploymentArtifacts({
        sourceEnvironment: SOURCE_ENVIRONMENT,
        manifest,
        signatureVerifier: () => true,
      }).manifest.sandboxArtifact
    ).toEqual(sandboxArtifact);
  });

  it("canonicalizes claims independently of object insertion order", () => {
    const claims = manifestClaims();
    const reordered: DaytonaDeploymentArtifactManifestClaims = {
      isolationProfile: claims.isolationProfile,
      sandboxArtifact: claims.sandboxArtifact,
      artifacts: claims.artifacts,
      source: claims.source,
      issuedAtMs: claims.issuedAtMs,
      manifestId: claims.manifestId,
      kind: claims.kind,
      version: claims.version,
    };
    expect(digestDaytonaDeploymentArtifactManifestClaims(reordered)).toBe(
      digestDaytonaDeploymentArtifactManifestClaims(claims)
    );
  });

  it("fails production activation before signature verification when the source pin is absent", () => {
    const signatureVerifier = vi.fn(() => true);
    expectErrorCode(
      () =>
        verifyDaytonaDeploymentArtifacts({
          sourceEnvironment: {},
          manifest: signedManifest(),
          signatureVerifier,
        }),
      "missing_source_pin"
    );
    expect(signatureVerifier).not.toHaveBeenCalled();
  });

  it.each([
    {
      label: "other fork",
      environment: {
        TERMINALX_DAYTONA_FORK_REPOSITORY: "https://github.com/example/daytona",
        TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT,
      },
    },
    {
      label: "floating commit",
      environment: {
        TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_FORK_REPOSITORY,
        TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: "main",
      },
    },
    {
      label: "other full commit",
      environment: {
        TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_FORK_REPOSITORY,
        TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: "a".repeat(40),
      },
    },
  ])("rejects $label before trusting a signed manifest", ({ environment }) => {
    const signatureVerifier = vi.fn(() => true);
    expectErrorCode(
      () =>
        verifyDaytonaDeploymentArtifacts({
          sourceEnvironment: environment,
          manifest: signedManifest(),
          signatureVerifier,
        }),
      "invalid_source_pin"
    );
    expect(signatureVerifier).not.toHaveBeenCalled();
  });

  it("rejects every mismatched signed source coordinate", () => {
    const sourceMutations: ReadonlyArray<Record<string, unknown>> = [
      { forkRepository: DAYTONA_UPSTREAM_REPOSITORY },
      { forkCommit: "a".repeat(40) },
      { upstreamRepository: DAYTONA_FORK_REPOSITORY },
      { upstreamBaseCommit: "a".repeat(40) },
    ];
    for (const mutation of sourceMutations) {
      const manifest = signedManifest();
      const mismatched = {
        ...manifest,
        source: { ...manifest.source, ...mutation },
      };
      expectErrorCode(() => verifyManifest(mismatched), "manifest_mismatch");
    }
  });

  it("rejects missing, extra, accessor-backed, symbol-bearing, and proxy manifests", () => {
    const manifest = signedManifest();
    const { authority: _authority, ...missingAuthority } = manifest;
    expectErrorCode(() => verifyManifest(missingAuthority), "invalid_manifest");
    expectErrorCode(() => verifyManifest({ ...manifest, extra: true }), "invalid_manifest");
    expectErrorCode(
      () => verifyManifest({ ...manifest, source: { ...manifest.source, extra: true } }),
      "invalid_manifest"
    );
    expectErrorCode(
      () => verifyManifest(Object.assign({ [Symbol("hostile")]: true }, manifest)),
      "invalid_manifest"
    );

    let getterInvoked = false;
    const accessor = Object.defineProperty({ ...manifest }, "authority", {
      enumerable: true,
      get() {
        getterInvoked = true;
        return manifest.authority;
      },
    });
    expectErrorCode(() => verifyManifest(accessor), "invalid_manifest");
    expect(getterInvoked).toBe(false);

    let proxyTrapInvoked = false;
    const proxy = new Proxy(manifest, {
      ownKeys() {
        proxyTrapInvoked = true;
        return [];
      },
    });
    expectErrorCode(() => verifyManifest(proxy), "invalid_manifest");
    expect(proxyTrapInvoked).toBe(false);
  });

  it("rejects malformed or aliased artifact digests and artifact kinds", () => {
    const manifest = signedManifest();
    const invalidManifests = [
      {
        ...manifest,
        artifacts: {
          ...manifest.artifacts,
          sdk: { ...manifest.artifacts.sdk, sha256: "a".repeat(63) },
        },
      },
      {
        ...manifest,
        artifacts: {
          ...manifest.artifacts,
          supervisor: {
            ...manifest.artifacts.supervisor,
            sha256: "A".repeat(64),
          },
        },
      },
      {
        ...manifest,
        artifacts: {
          ...manifest.artifacts,
          sbom: { ...manifest.artifacts.sbom, kind: "cyclonedx-json" },
        },
      },
      {
        ...manifest,
        artifacts: {
          ...manifest.artifacts,
          provenance: { ...manifest.artifacts.provenance, extra: true },
        },
      },
      {
        ...manifest,
        artifacts: {
          ...manifest.artifacts,
          runtimeArtifactManifest: {
            ...manifest.artifacts.runtimeArtifactManifest,
            kind: "terminalx.runtime-artifacts",
          },
          runner: { ...manifest.artifacts.runner, kind: "daytona-runner" },
        },
      },
      {
        ...manifest,
        artifacts: {
          ...manifest.artifacts,
          daemon: { ...manifest.artifacts.daemon, sha256: DIGESTS.runner },
        },
      },
      {
        ...manifest,
        artifacts: {
          ...manifest.artifacts,
          supervisor: { ...manifest.artifacts.supervisor, sha256: DIGESTS.sdk },
        },
      },
    ];
    for (const invalid of invalidManifests) {
      expectErrorCode(() => verifyManifest(invalid), "invalid_manifest");
    }
  });

  it("rejects legacy v1 manifests instead of implicitly upgrading their trust statement", () => {
    const manifest = signedManifest();
    expectErrorCode(() => verifyManifest({ ...manifest, version: 1 }), "invalid_manifest");
  });

  it("rejects floating, unpinned, or internally mismatched image and snapshot sources", () => {
    const manifest = signedManifest();
    const snapshot = {
      kind: "daytona-snapshot",
      snapshotId: SNAPSHOT_ID,
      snapshotRef: SNAPSHOT_REF,
      imageId: SNAPSHOT_IMAGE_ID,
      sha256: DIGESTS.snapshot,
    } as const;
    const invalidArtifacts: unknown[] = [
      {
        kind: "oci-image",
        reference: "ghcr.io/procyon-labs-io/terminalx:latest",
        sha256: DIGESTS.sandbox,
      },
      {
        kind: "oci-image",
        reference: `ghcr.io/procyon-labs-io/terminalx@sha256:${"a".repeat(64)}`,
        sha256: DIGESTS.sandbox,
      },
      {
        kind: "oci-image",
        reference: `https://ghcr.io/procyon-labs-io/terminalx@sha256:${DIGESTS.sandbox}`,
        sha256: DIGESTS.sandbox,
      },
      { ...snapshot, snapshotId: "latest" },
      {
        ...snapshot,
        snapshotId: "123e4567-e89b-12d3-a456-426614174000",
      },
      {
        ...snapshot,
        snapshotId: "123E4567-E89B-42D3-A456-426614174000",
      },
      {
        ...snapshot,
        snapshotRef: `registry.example.com/terminalx/sandbox:latest`,
      },
      {
        ...snapshot,
        snapshotRef: `registry.example.com/terminalx/sandbox@sha256:${"a".repeat(64)}`,
      },
      { ...snapshot, imageId: "8".repeat(64) },
      {
        ...snapshot,
        sha256: "A".repeat(64),
      },
    ];
    for (const sandboxArtifact of invalidArtifacts) {
      expectErrorCode(() => verifyManifest({ ...manifest, sandboxArtifact }), "invalid_manifest");
    }
  });

  it("rejects floating, malformed, and digest-aliased isolation profiles", () => {
    const manifest = signedManifest();
    for (const isolationProfile of [
      { profileRef: "default", sha256: DIGESTS.isolation },
      { profileRef: "profile with spaces", sha256: DIGESTS.isolation },
      { profileRef: "terminalx-isolation:v1", sha256: "f".repeat(63) },
      { profileRef: "terminalx-isolation:v1", sha256: DIGESTS.sdk },
    ]) {
      expectErrorCode(() => verifyManifest({ ...manifest, isolationProfile }), "invalid_manifest");
    }
  });

  it("recomputes the claims digest and validates the closed authority statement", () => {
    const manifest = signedManifest();
    const signatureVerifier = vi.fn(() => true);
    expectErrorCode(
      () =>
        verifyManifest(
          {
            ...manifest,
            authority: { ...manifest.authority, claimsDigest: "a".repeat(64) },
          },
          signatureVerifier
        ),
      "manifest_mismatch"
    );
    expect(signatureVerifier).not.toHaveBeenCalled();

    for (const authority of [
      { ...manifest.authority, issuer: "other-release" },
      { ...manifest.authority, audience: "browser" },
      { ...manifest.authority, capability: "daytona.deploy" },
      { ...manifest.authority, algorithm: "rsa" },
      { ...manifest.authority, extra: true },
    ]) {
      expectErrorCode(() => verifyManifest({ ...manifest, authority }), "invalid_manifest");
    }
    expectErrorCode(
      () =>
        verifyManifest({
          ...manifest,
          authority: { ...manifest.authority, signature: "not-a-signature" },
        }),
      "invalid_signature"
    );
    expectErrorCode(
      () =>
        verifyManifest({
          ...manifest,
          authority: {
            ...manifest.authority,
            signature: `${SIGNATURE.slice(0, -1)}B`,
          },
        }),
      "invalid_signature"
    );
  });

  it("fails closed for rejecting, throwing, asynchronous, thenable, or proxied verifiers", async () => {
    expectErrorCode(() => verifyManifest(signedManifest(), () => false), "invalid_signature");
    expectErrorCode(
      () =>
        verifyManifest(signedManifest(), () => {
          throw new Error("private verifier detail");
        }),
      "invalid_signature"
    );

    const rejected = Promise.reject(new Error("private asynchronous verifier detail"));
    expectErrorCode(
      () =>
        verifyManifest(
          signedManifest(),
          (() => rejected) as unknown as DaytonaDeploymentManifestSignatureVerifier
        ),
      "invalid_signature"
    );
    await Promise.resolve();

    let thenGetterInvoked = false;
    const thenable = Object.defineProperty({}, "then", {
      get() {
        thenGetterInvoked = true;
        return () => undefined;
      },
    });
    expectErrorCode(
      () =>
        verifyManifest(
          signedManifest(),
          (() => thenable) as unknown as DaytonaDeploymentManifestSignatureVerifier
        ),
      "invalid_signature"
    );
    expect(thenGetterInvoked).toBe(false);

    let applyTrapInvoked = false;
    const proxy = new Proxy((() => true) as DaytonaDeploymentManifestSignatureVerifier, {
      apply() {
        applyTrapInvoked = true;
        return true;
      },
    });
    expectErrorCode(() => verifyManifest(signedManifest(), proxy), "invalid_configuration");
    expect(applyTrapInvoked).toBe(false);
  });

  it("rejects absent or noncanonical verification options", () => {
    expectErrorCode(
      () => verifyDaytonaDeploymentArtifacts(undefined as never),
      "invalid_configuration"
    );
    expectErrorCode(
      () =>
        verifyDaytonaDeploymentArtifacts({
          sourceEnvironment: undefined,
          manifest: signedManifest(),
          signatureVerifier: () => true,
        } as never),
      "invalid_configuration"
    );
    expectErrorCode(
      () =>
        verifyDaytonaDeploymentArtifacts({
          sourceEnvironment: SOURCE_ENVIRONMENT,
          manifest: signedManifest(),
        } as never),
      "invalid_configuration"
    );
    expectErrorCode(
      () =>
        verifyDaytonaDeploymentArtifacts({
          sourceEnvironment: SOURCE_ENVIRONMENT,
          manifest: signedManifest(),
          signatureVerifier: () => true,
          extra: true,
        } as never),
      "invalid_configuration"
    );
  });
});

function manifestClaims(
  sandboxArtifact: DaytonaImmutableSandboxArtifact = {
    kind: "oci-image",
    reference: `ghcr.io/procyon-labs-io/terminalx-daytona@sha256:${DIGESTS.sandbox}`,
    sha256: DIGESTS.sandbox,
  }
): DaytonaDeploymentArtifactManifestClaims {
  return {
    version: 2,
    kind: "terminalx.daytona-deployment-artifacts",
    manifestId: "terminalx-daytona-production:2026-07-24:v2",
    issuedAtMs: 2_000_000_000_000,
    source: {
      forkRepository: DAYTONA_FORK_REPOSITORY,
      forkCommit: DAYTONA_PRODUCTION_FORK_COMMIT,
      upstreamRepository: DAYTONA_UPSTREAM_REPOSITORY,
      upstreamBaseCommit: DAYTONA_UPSTREAM_BASE_COMMIT,
    },
    artifacts: {
      sdk: { kind: "daytona-typescript-sdk", sha256: DIGESTS.sdk },
      supervisor: { kind: "terminalx-daytona-supervisor", sha256: DIGESTS.supervisor },
      runtimeArtifactManifest: {
        kind: "terminalx-daytona-hardened-runtime-artifacts",
        sha256: DIGESTS.runtimeArtifactManifest,
      },
      runner: { kind: "daytona-hardened-runner-linux-amd64", sha256: DIGESTS.runner },
      daemon: { kind: "daytona-hardened-daemon-linux-amd64", sha256: DIGESTS.daemon },
      sbom: { kind: "spdx-2.3-json", sha256: DIGESTS.sbom },
      provenance: { kind: "slsa-v1-dsse", sha256: DIGESTS.provenance },
    },
    sandboxArtifact,
    isolationProfile: {
      profileRef: "terminalx-daytona-isolation:v1",
      sha256: DIGESTS.isolation,
    },
  };
}

function signedManifest(
  claims: DaytonaDeploymentArtifactManifestClaims = manifestClaims()
): DaytonaDeploymentArtifactManifest {
  return {
    ...claims,
    authority: {
      issuer: "terminalx-release",
      issuerKeyId: "terminalx-release:daytona-production:v2",
      audience: "terminalx-runtime",
      capability: "daytona.deployment.activate",
      algorithm: "ed25519",
      claimsDigest: digestDaytonaDeploymentArtifactManifestClaims(claims),
      signature: SIGNATURE,
    },
  };
}

function verifyManifest(
  manifest: unknown,
  signatureVerifier: DaytonaDeploymentManifestSignatureVerifier = () => true
) {
  return verifyDaytonaDeploymentArtifacts({
    sourceEnvironment: SOURCE_ENVIRONMENT,
    manifest,
    signatureVerifier,
  });
}

function expectErrorCode(
  operation: () => unknown,
  expectedCode: DaytonaDeploymentArtifactErrorCode
): void {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(DaytonaDeploymentArtifactError);
    expect((error as DaytonaDeploymentArtifactError).code).toBe(expectedCode);
    return;
  }
  throw new Error(`Expected DaytonaDeploymentArtifactError:${expectedCode}`);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
