import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
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
  it("keeps every release surface on the reviewed hardened merge", () => {
    expect(DAYTONA_PRODUCTION_FORK_COMMIT).toBe("f9b4dfe428d37f3d956acda4403879516aa8d923");
    expect(DAYTONA_PRODUCTION_FORK_COMMIT).not.toBe(DAYTONA_UPSTREAM_BASE_COMMIT);
    for (const relativePath of [
      ".github/workflows/daytona-sdk-artifact.yml",
      "scripts/build-pinned-daytona-sdk.sh",
      "scripts/build-pinned-daytona-supervisor.sh",
      "scripts/write-daytona-sdk-artifact.mjs",
      "scripts/write-daytona-supervisor-artifact.mjs",
      "packages/daytona-sandbox-image/scripts/prepare-build-context.mjs",
      "packages/daytona-sandbox-image/scripts/write-static-pins.mjs",
    ]) {
      expect(readFileSync(resolve(process.cwd(), relativePath), "utf8"), relativePath).toContain(
        DAYTONA_PRODUCTION_FORK_COMMIT
      );
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
        issuerKeyId: "terminalx-release:daytona-production:v1",
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
          supervisor: { ...manifest.artifacts.supervisor, sha256: DIGESTS.sdk },
        },
      },
    ];
    for (const invalid of invalidManifests) {
      expectErrorCode(() => verifyManifest(invalid), "invalid_manifest");
    }
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
    version: 1,
    kind: "terminalx.daytona-deployment-artifacts",
    manifestId: "terminalx-daytona-production:2026-07-24:v1",
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
      issuerKeyId: "terminalx-release:daytona-production:v1",
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
