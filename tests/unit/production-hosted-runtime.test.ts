import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT,
  installConfiguredProductionHostedRuntimeFactory,
  loadProductionHostedRuntimeConfiguration,
} from "../../server/production-hosted-runtime";
import type { DaytonaHostedMultiplayerService } from "../../src/lib/runtime/hosted-multiplayer-service";
import { canonicalRuntimeJson } from "../../src/lib/runtime/runtime-command-canonical";
import { getHostedMultiplayerServiceFactory } from "../../src/lib/team-sessions/service";

interface IdentityFixture {
  readonly keyId: string;
  readonly privateKey: KeyObject;
  readonly publicKeySpkiPem: string;
}

interface HostedConfigurationFixture {
  readonly directory: string;
  readonly environment: Record<string, string>;
  readonly identities: {
    readonly bootstrapAuthority: IdentityFixture;
    readonly teamCommandAuthority: IdentityFixture;
    readonly platformCompensationAuthority: IdentityFixture;
  };
  readonly paths: {
    readonly runtimeConfiguration: string;
    readonly daytonaApiCredential: string;
    readonly runnerCredential: string;
    readonly assignmentMasterKey: string;
    readonly bootstrapAuthorityPrivateKey: string;
    readonly teamCommandAuthorityPrivateKey: string;
    readonly platformCompensationAuthorityPrivateKey: string;
    readonly opaqueHandleKey: string;
  };
}

const directories: string[] = [];
const uninstallers: Array<() => void> = [];

afterEach(() => {
  for (const uninstall of uninstallers.splice(0)) uninstall();
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

describe("production hosted Runtime configuration", () => {
  it("preserves disabled behavior without reading dormant hosted paths", () => {
    const environment = {
      NODE_ENV: "production",
      TERMINALX_MULTIPLAYER_ENABLED: "true",
      TERMINALX_HOSTED_RUNTIME_ENABLED: "true",
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.trustRoot]: "/not/read",
    };

    const configuration = loadProductionHostedRuntimeConfiguration(environment);
    expect(configuration.enabled).toBe(false);
    expect(() => configuration.close()).not.toThrow();
    const uninstall = installConfiguredProductionHostedRuntimeFactory(undefined, environment);
    expect(getHostedMultiplayerServiceFactory()).toBeNull();
    uninstall();
  });

  it("accepts only the exact production Daytona selector with multiplayer enabled", () => {
    for (const environment of [
      {
        TERMINALX_HOSTED_RUNTIME: "true",
        NODE_ENV: "production",
        TERMINALX_MULTIPLAYER_ENABLED: "true",
      },
      {
        TERMINALX_HOSTED_RUNTIME: "daytona",
        NODE_ENV: "development",
        TERMINALX_MULTIPLAYER_ENABLED: "true",
      },
      {
        TERMINALX_HOSTED_RUNTIME: "daytona",
        NODE_ENV: "production",
        TERMINALX_MULTIPLAYER_ENABLED: "false",
      },
    ]) {
      expect(() => loadProductionHostedRuntimeConfiguration(environment)).toThrow(
        expect.objectContaining({ code: "invalid-enablement" })
      );
    }
  });

  it("loads canonical public pins and owned bounded private material from protected files", () => {
    const fixture = createFixture();
    const configuration = loadProductionHostedRuntimeConfiguration(fixture.environment);
    if (!configuration.enabled) throw new Error("expected enabled fixture");

    expect(configuration.publicConfiguration).toMatchObject({
      version: 1,
      kind: "terminalx.daytona-hosted-runtime-configuration",
      identities: {
        bootstrapAuthority: { keyId: "bootstrap-authority:v1" },
        teamCommandAuthority: { keyId: "team-command-authority:v1" },
        platformCompensationAuthority: { keyId: "platform-compensation-authority:v1" },
      },
      settings: { deployment: { source: "pinned-test-fixture" } },
    });
    expect(configuration.publicConfiguration.fileSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(configuration.privateMaterial.assignmentMasterKey).toHaveLength(32);
    expect(configuration.privateMaterial.opaqueHandleKey).toHaveLength(32);
    expect(configuration.privateFiles).toEqual({
      bootstrapAuthorityPrivateKey: fixture.paths.bootstrapAuthorityPrivateKey,
      teamCommandAuthorityPrivateKey: fixture.paths.teamCommandAuthorityPrivateKey,
      platformCompensationAuthorityPrivateKey:
        fixture.paths.platformCompensationAuthorityPrivateKey,
    });
    expect(
      configuration.privateMaterial.bootstrapAuthorityPrivateKeyPkcs8.some((byte) => byte !== 0)
    ).toBe(true);

    const owned: readonly Uint8Array[] = [
      configuration.privateMaterial.assignmentMasterKey,
      configuration.privateMaterial.bootstrapAuthorityPrivateKeyPkcs8,
      configuration.privateMaterial.teamCommandAuthorityPrivateKeyPkcs8,
      configuration.privateMaterial.platformCompensationAuthorityPrivateKeyPkcs8,
      configuration.privateMaterial.daytonaApiCredential,
      configuration.privateMaterial.runnerCredential,
      configuration.privateMaterial.opaqueHandleKey,
    ];
    configuration.close();
    configuration.close();
    expect(owned.every((bytes) => bytes.every((byte) => byte === 0))).toBe(true);
  });

  it("installs one one-shot factory, then zeroes every leased byte", async () => {
    const fixture = createFixture();
    let captured: readonly Uint8Array[] = [];
    const service = Object.freeze({
      test: "service",
    }) as unknown as DaytonaHostedMultiplayerService;
    const uninstall = installConfiguredProductionHostedRuntimeFactory(async (configuration) => {
      captured = Object.values(configuration.privateMaterial);
      expect(captured.every((bytes) => bytes.some((byte) => byte !== 0))).toBe(true);
      return service;
    }, fixture.environment);
    uninstallers.push(uninstall);

    const factory = getHostedMultiplayerServiceFactory();
    expect(factory).not.toBeNull();
    await expect(factory?.()).resolves.toBe(service);
    expect(captured.every((bytes) => bytes.every((byte) => byte === 0))).toBe(true);
    await expect(factory?.()).rejects.toMatchObject({ code: "composition-unavailable" });

    uninstall();
    expect(getHostedMultiplayerServiceFactory()).toBeNull();
  });

  it("fails enabled startup when the concrete composer is not installed", () => {
    const fixture = createFixture();
    expect(() =>
      installConfiguredProductionHostedRuntimeFactory(undefined, fixture.environment)
    ).toThrow(expect.objectContaining({ code: "composition-unavailable" }));
    expect(getHostedMultiplayerServiceFactory()).toBeNull();
  });

  it("rejects noncanonical configuration bytes and unprotected files", () => {
    const fixture = createFixture();
    const canonical = configurationDocument(fixture.identities);
    writeFileSync(fixture.paths.runtimeConfiguration, `${canonical}\n\n`, { mode: 0o600 });
    expect(() => loadProductionHostedRuntimeConfiguration(fixture.environment)).toThrow(
      expect.objectContaining({ code: "invalid-configuration" })
    );

    writeFileSync(fixture.paths.runtimeConfiguration, `${canonical}\n`, { mode: 0o600 });
    chmodSync(fixture.paths.daytonaApiCredential, 0o644);
    expect(() => loadProductionHostedRuntimeConfiguration(fixture.environment)).toThrow(
      expect.objectContaining({ code: "configuration-unavailable" })
    );
  });

  it("requires an exact nonzero assignment master and bounded raw credentials", () => {
    const fixture = createFixture();
    writeFileSync(fixture.paths.assignmentMasterKey, Buffer.alloc(31, 1), { mode: 0o600 });
    expect(() => loadProductionHostedRuntimeConfiguration(fixture.environment)).toThrow(
      expect.objectContaining({ code: "configuration-unavailable" })
    );

    writeFileSync(fixture.paths.assignmentMasterKey, Buffer.alloc(32, 1), { mode: 0o600 });
    writeFileSync(fixture.paths.daytonaApiCredential, "credential-with-newline\n", { mode: 0o600 });
    expect(() => loadProductionHostedRuntimeConfiguration(fixture.environment)).toThrow(
      expect.objectContaining({ code: "invalid-private-material" })
    );

    writeFileSync(fixture.paths.daytonaApiCredential, "daytona-api-credential", { mode: 0o600 });
    writeFileSync(fixture.paths.assignmentMasterKey, Buffer.alloc(32), { mode: 0o600 });
    expect(() => loadProductionHostedRuntimeConfiguration(fixture.environment)).toThrow(
      expect.objectContaining({ code: "invalid-private-material" })
    );
  });

  it("requires exact canonical unencrypted Ed25519 PKCS8 PEM matching every public pin", () => {
    const fixture = createFixture();
    const der = fixture.identities.bootstrapAuthority.privateKey.export({
      type: "pkcs8",
      format: "der",
    });
    writeFileSync(fixture.paths.bootstrapAuthorityPrivateKey, der, { mode: 0o600 });
    expect(() => loadProductionHostedRuntimeConfiguration(fixture.environment)).toThrow(
      expect.objectContaining({ code: "invalid-private-material" })
    );

    const canonicalPem = fixture.identities.bootstrapAuthority.privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    writeFileSync(fixture.paths.bootstrapAuthorityPrivateKey, canonicalPem.slice(0, -1), {
      mode: 0o600,
    });
    expect(() => loadProductionHostedRuntimeConfiguration(fixture.environment)).toThrow(
      expect.objectContaining({ code: "invalid-private-material" })
    );

    writePrivateKey(
      fixture.paths.bootstrapAuthorityPrivateKey,
      fixture.identities.teamCommandAuthority.privateKey
    );
    expect(() => loadProductionHostedRuntimeConfiguration(fixture.environment)).toThrow(
      expect.objectContaining({ code: "identity-reuse" })
    );
  });

  it("rejects key-id, SPKI, file-path, and unknown hosted-variable reuse", () => {
    const duplicateIdFixture = createFixture();
    writeConfiguration(duplicateIdFixture, {
      ...duplicateIdFixture.identities,
      teamCommandAuthority: {
        ...duplicateIdFixture.identities.teamCommandAuthority,
        keyId: duplicateIdFixture.identities.bootstrapAuthority.keyId,
      },
    });
    expect(() => loadProductionHostedRuntimeConfiguration(duplicateIdFixture.environment)).toThrow(
      expect.objectContaining({ code: "identity-reuse" })
    );

    const duplicateSpkiFixture = createFixture();
    writeConfiguration(duplicateSpkiFixture, {
      ...duplicateSpkiFixture.identities,
      teamCommandAuthority: {
        ...duplicateSpkiFixture.identities.teamCommandAuthority,
        publicKeySpkiPem: duplicateSpkiFixture.identities.bootstrapAuthority.publicKeySpkiPem,
      },
    });
    expect(() =>
      loadProductionHostedRuntimeConfiguration(duplicateSpkiFixture.environment)
    ).toThrow(expect.objectContaining({ code: "identity-reuse" }));

    const duplicatePathFixture = createFixture();
    duplicatePathFixture.environment[
      PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.teamCommandAuthorityPrivateKeyFile
    ] = duplicatePathFixture.paths.bootstrapAuthorityPrivateKey;
    expect(() =>
      loadProductionHostedRuntimeConfiguration(duplicatePathFixture.environment)
    ).toThrow(expect.objectContaining({ code: "identity-reuse" }));

    const duplicateCredentialFixture = createFixture();
    writeFileSync(duplicateCredentialFixture.paths.runnerCredential, "daytona-api-credential", {
      mode: 0o600,
    });
    expect(() =>
      loadProductionHostedRuntimeConfiguration(duplicateCredentialFixture.environment)
    ).toThrow(expect.objectContaining({ code: "identity-reuse" }));

    const unknownVariableFixture = createFixture();
    unknownVariableFixture.environment.TERMINALX_HOSTED_API_CREDENTIAL = "secret-in-env";
    expect(() =>
      loadProductionHostedRuntimeConfiguration(unknownVariableFixture.environment)
    ).toThrow(expect.objectContaining({ code: "invalid-configuration" }));
  });
});

function createFixture(): HostedConfigurationFixture {
  const directory = mkdtempSync(join(tmpdir(), "terminalx-hosted-runtime-"));
  directories.push(directory);
  chmodSync(directory, 0o700);
  const identities = {
    bootstrapAuthority: identity("bootstrap-authority:v1"),
    teamCommandAuthority: identity("team-command-authority:v1"),
    platformCompensationAuthority: identity("platform-compensation-authority:v1"),
  } as const;
  const paths = {
    runtimeConfiguration: join(directory, "runtime.json"),
    daytonaApiCredential: join(directory, "daytona-api.credential"),
    runnerCredential: join(directory, "runner.credential"),
    assignmentMasterKey: join(directory, "assignment-master.key"),
    bootstrapAuthorityPrivateKey: join(directory, "bootstrap-authority.pkcs8"),
    teamCommandAuthorityPrivateKey: join(directory, "team-command-authority.pkcs8"),
    platformCompensationAuthorityPrivateKey: join(
      directory,
      "platform-compensation-authority.pkcs8"
    ),
    opaqueHandleKey: join(directory, "opaque-handle.key"),
  } as const;
  const fixture: HostedConfigurationFixture = {
    directory,
    identities,
    paths,
    environment: {
      NODE_ENV: "production",
      TERMINALX_MULTIPLAYER_ENABLED: "true",
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.runtime]: "daytona",
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.trustRoot]: directory,
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.runtimeConfigurationFile]: paths.runtimeConfiguration,
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.daytonaApiCredentialFile]: paths.daytonaApiCredential,
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.runnerCredentialFile]: paths.runnerCredential,
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.assignmentMasterKeyFile]: paths.assignmentMasterKey,
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.bootstrapAuthorityPrivateKeyFile]:
        paths.bootstrapAuthorityPrivateKey,
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.teamCommandAuthorityPrivateKeyFile]:
        paths.teamCommandAuthorityPrivateKey,
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.platformCompensationAuthorityPrivateKeyFile]:
        paths.platformCompensationAuthorityPrivateKey,
      [PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.opaqueHandleKeyFile]: paths.opaqueHandleKey,
    },
  };
  writeConfiguration(fixture, identities);
  writeFileSync(paths.daytonaApiCredential, "daytona-api-credential", { mode: 0o600 });
  writeFileSync(paths.runnerCredential, "runner-credential", { mode: 0o600 });
  writeFileSync(paths.assignmentMasterKey, Buffer.alloc(32, 0x31), { mode: 0o600 });
  writePrivateKey(paths.bootstrapAuthorityPrivateKey, identities.bootstrapAuthority.privateKey);
  writePrivateKey(paths.teamCommandAuthorityPrivateKey, identities.teamCommandAuthority.privateKey);
  writePrivateKey(
    paths.platformCompensationAuthorityPrivateKey,
    identities.platformCompensationAuthority.privateKey
  );
  writeFileSync(paths.opaqueHandleKey, Buffer.alloc(32, 0x41), { mode: 0o600 });
  return fixture;
}

function identity(keyId: string): IdentityFixture {
  const keys = generateKeyPairSync("ed25519");
  return {
    keyId,
    privateKey: keys.privateKey,
    publicKeySpkiPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

function configurationDocument(identities: HostedConfigurationFixture["identities"]): string {
  return canonicalRuntimeJson({
    version: 1,
    kind: "terminalx.daytona-hosted-runtime-configuration",
    identities: {
      bootstrapAuthority: publicIdentity(identities.bootstrapAuthority),
      teamCommandAuthority: publicIdentity(identities.teamCommandAuthority),
      platformCompensationAuthority: publicIdentity(identities.platformCompensationAuthority),
    },
    settings: { deployment: { source: "pinned-test-fixture" } },
  });
}

function writeConfiguration(
  fixture: HostedConfigurationFixture,
  identities: HostedConfigurationFixture["identities"]
): void {
  writeFileSync(fixture.paths.runtimeConfiguration, `${configurationDocument(identities)}\n`, {
    mode: 0o600,
  });
}

function publicIdentity(value: IdentityFixture) {
  return { keyId: value.keyId, publicKeySpkiPem: value.publicKeySpkiPem };
}

function writePrivateKey(filePath: string, privateKey: KeyObject): void {
  writeFileSync(filePath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
}
