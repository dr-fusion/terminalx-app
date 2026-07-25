import { createHash, createPrivateKey, createPublicKey, timingSafeEqual } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { types as nodeTypes } from "node:util";
import type { DaytonaHostedMultiplayerService } from "../src/lib/runtime/hosted-multiplayer-service";
import { canonicalRuntimeJson } from "../src/lib/runtime/runtime-command-canonical";
import { readTrustedConfigurationFile } from "../src/lib/runtime/runtime-trusted-configuration-file";
import { installHostedMultiplayerServiceFactory } from "../src/lib/team-sessions/service";

export const PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT = Object.freeze({
  runtime: "TERMINALX_HOSTED_RUNTIME",
  trustRoot: "TERMINALX_HOSTED_TRUST_ROOT",
  runtimeConfigurationFile: "TERMINALX_HOSTED_RUNTIME_CONFIG_FILE",
  daytonaApiCredentialFile: "TERMINALX_HOSTED_DAYTONA_API_CREDENTIAL_FILE",
  runnerCredentialFile: "TERMINALX_HOSTED_RUNNER_CREDENTIAL_FILE",
  assignmentMasterKeyFile: "TERMINALX_HOSTED_ASSIGNMENT_MASTER_KEY_FILE",
  bootstrapAuthorityPrivateKeyFile: "TERMINALX_HOSTED_BOOTSTRAP_AUTHORITY_PRIVATE_KEY_FILE",
  teamCommandAuthorityPrivateKeyFile: "TERMINALX_HOSTED_TEAM_COMMAND_AUTHORITY_PRIVATE_KEY_FILE",
  platformCompensationAuthorityPrivateKeyFile:
    "TERMINALX_HOSTED_PLATFORM_COMPENSATION_AUTHORITY_PRIVATE_KEY_FILE",
  opaqueHandleKeyFile: "TERMINALX_HOSTED_OPAQUE_HANDLE_KEY_FILE",
} as const);

const HOSTED_ENVIRONMENT_PREFIX = "TERMINALX_HOSTED_";
const HOSTED_RUNTIME = "daytona" as const;
const CONFIGURATION_KIND = "terminalx.daytona-hosted-runtime-configuration" as const;
const CONFIGURATION_FIELDS = new Set(["version", "kind", "identities", "settings"]);
const IDENTITY_FIELDS = new Set([
  "bootstrapAuthority",
  "teamCommandAuthority",
  "platformCompensationAuthority",
]);
const PINNED_IDENTITY_FIELDS = new Set(["keyId", "publicKeySpkiPem"]);
const KNOWN_HOSTED_ENVIRONMENT_KEYS: ReadonlySet<string> = new Set<string>(
  Object.values(PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT)
);
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const MAX_CONFIGURATION_BYTES = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES = 4096;
const MAX_PUBLIC_KEY_BYTES = 4096;
const MAX_CREDENTIAL_BYTES = 8192;
const MIN_OPAQUE_HANDLE_KEY_BYTES = 32;
const MAX_OPAQUE_HANDLE_KEY_BYTES = 64;
const ASSIGNMENT_MASTER_KEY_BYTES = 32;

export type ProductionHostedRuntimeConfigurationErrorCode =
  | "invalid-enablement"
  | "incomplete-configuration"
  | "configuration-unavailable"
  | "invalid-configuration"
  | "invalid-private-material"
  | "identity-reuse"
  | "composition-unavailable";

const SAFE_ERROR_MESSAGES: Readonly<Record<ProductionHostedRuntimeConfigurationErrorCode, string>> =
  Object.freeze({
    "invalid-enablement": "Production hosted Runtime enablement is invalid",
    "incomplete-configuration": "Production hosted Runtime configuration is incomplete",
    "configuration-unavailable": "Production hosted Runtime configuration is unavailable",
    "invalid-configuration": "Production hosted Runtime configuration is invalid",
    "invalid-private-material": "Production hosted Runtime private material is invalid",
    "identity-reuse": "Production hosted Runtime identities are not separated",
    "composition-unavailable": "Production hosted Runtime composition is unavailable",
  });

export class ProductionHostedRuntimeConfigurationError extends Error {
  constructor(readonly code: ProductionHostedRuntimeConfigurationErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "ProductionHostedRuntimeConfigurationError";
  }
}

export interface ProductionHostedRuntimePinnedIdentity {
  readonly keyId: string;
  readonly publicKeySpkiPem: string;
  readonly publicKeySpkiSha256: string;
}

export interface ProductionHostedRuntimePublicConfiguration {
  readonly version: 1;
  readonly kind: typeof CONFIGURATION_KIND;
  readonly identities: {
    readonly bootstrapAuthority: ProductionHostedRuntimePinnedIdentity;
    readonly teamCommandAuthority: ProductionHostedRuntimePinnedIdentity;
    readonly platformCompensationAuthority: ProductionHostedRuntimePinnedIdentity;
  };
  /** The concrete composer must exact-validate this complete public settings record. */
  readonly settings: Readonly<Record<string, unknown>>;
  /** SHA-256 of the exact canonical JSON plus its required trailing LF. */
  readonly fileSha256: string;
}

export interface ProductionHostedRuntimePrivateMaterial {
  /** Exactly 32 owned bytes. */
  readonly assignmentMasterKey: Uint8Array;
  /** Exact canonical unencrypted Ed25519 PKCS8 PEM owned bytes. */
  readonly bootstrapAuthorityPrivateKeyPkcs8: Uint8Array;
  /** Exact canonical unencrypted Ed25519 PKCS8 PEM owned bytes. */
  readonly teamCommandAuthorityPrivateKeyPkcs8: Uint8Array;
  /** Exact canonical unencrypted Ed25519 PKCS8 PEM owned bytes. */
  readonly platformCompensationAuthorityPrivateKeyPkcs8: Uint8Array;
  /** Bounded raw owned bytes; never decoded into an environment string. */
  readonly daytonaApiCredential: Uint8Array;
  /** Bounded raw owned bytes; never decoded into an environment string. */
  readonly runnerCredential: Uint8Array;
  /** Between 32 and 64 owned bytes. */
  readonly opaqueHandleKey: Uint8Array;
}

export interface ProductionHostedRuntimePrivateFiles {
  readonly bootstrapAuthorityPrivateKey: string;
  readonly teamCommandAuthorityPrivateKey: string;
  readonly platformCompensationAuthorityPrivateKey: string;
}

export interface EnabledProductionHostedRuntimeConfiguration {
  readonly enabled: true;
  readonly trustedConfigurationRoot: string;
  readonly publicConfiguration: ProductionHostedRuntimePublicConfiguration;
  /** Validated paths for constructors whose hardened API owns its own file read. */
  readonly privateFiles: ProductionHostedRuntimePrivateFiles;
  /**
   * The concrete composer must synchronously transfer/copy every needed value
   * into its owning constructors before its Promise settles. This lease zeroes
   * every byte whether composition succeeds, rejects, or is never invoked.
   */
  readonly privateMaterial: ProductionHostedRuntimePrivateMaterial;
  readonly close: () => void;
}

export interface DisabledProductionHostedRuntimeConfiguration {
  readonly enabled: false;
  readonly close: () => void;
}

export type ProductionHostedRuntimeConfiguration =
  | EnabledProductionHostedRuntimeConfiguration
  | DisabledProductionHostedRuntimeConfiguration;

export type ProductionHostedRuntimeComposer = (
  configuration: EnabledProductionHostedRuntimeConfiguration
) => Promise<DaytonaHostedMultiplayerService>;

const DISABLED_CONFIGURATION: DisabledProductionHostedRuntimeConfiguration = Object.freeze({
  enabled: false,
  close: Object.freeze(() => undefined),
});

/**
 * Load the production contract without reading any private file while hosted
 * execution is disabled. The only enabling value is the exact string
 * `daytona`; typos and legacy boolean flags fail closed.
 */
export function loadProductionHostedRuntimeConfiguration(
  environment: Readonly<Record<string, string | undefined>> = process.env
): ProductionHostedRuntimeConfiguration {
  const runtime = environmentValue(environment, PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.runtime);
  if (runtime === undefined) return DISABLED_CONFIGURATION;
  if (runtime !== HOSTED_RUNTIME) configurationError("invalid-enablement");
  if (
    environmentValue(environment, "NODE_ENV") !== "production" ||
    environmentValue(environment, "TERMINALX_MULTIPLAYER_ENABLED") !== "true"
  ) {
    configurationError("invalid-enablement");
  }
  assertNoUnknownHostedEnvironmentKeys(environment);

  const trustedConfigurationRoot = requiredCanonicalAbsolutePath(
    environment,
    PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.trustRoot
  );
  const paths = Object.freeze({
    runtimeConfiguration: requiredCanonicalAbsolutePath(
      environment,
      PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.runtimeConfigurationFile
    ),
    daytonaApiCredential: requiredCanonicalAbsolutePath(
      environment,
      PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.daytonaApiCredentialFile
    ),
    runnerCredential: requiredCanonicalAbsolutePath(
      environment,
      PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.runnerCredentialFile
    ),
    assignmentMasterKey: requiredCanonicalAbsolutePath(
      environment,
      PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.assignmentMasterKeyFile
    ),
    bootstrapAuthorityPrivateKey: requiredCanonicalAbsolutePath(
      environment,
      PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.bootstrapAuthorityPrivateKeyFile
    ),
    teamCommandAuthorityPrivateKey: requiredCanonicalAbsolutePath(
      environment,
      PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.teamCommandAuthorityPrivateKeyFile
    ),
    platformCompensationAuthorityPrivateKey: requiredCanonicalAbsolutePath(
      environment,
      PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.platformCompensationAuthorityPrivateKeyFile
    ),
    opaqueHandleKey: requiredCanonicalAbsolutePath(
      environment,
      PRODUCTION_HOSTED_RUNTIME_ENVIRONMENT.opaqueHandleKeyFile
    ),
  });
  if (new Set(Object.values(paths)).size !== Object.values(paths).length) {
    configurationError("identity-reuse");
  }

  let configurationBytes: Buffer | undefined;
  try {
    configurationBytes = trustedRead(
      trustedConfigurationRoot,
      paths.runtimeConfiguration,
      3,
      MAX_CONFIGURATION_BYTES
    );
    const decoded = decodePublicConfiguration(configurationBytes);

    const owned: Buffer[] = [];
    const capture = (bytes: Buffer): Buffer => {
      owned.push(bytes);
      return bytes;
    };
    try {
      const daytonaApiCredential = capture(
        trustedRead(trustedConfigurationRoot, paths.daytonaApiCredential, 1, MAX_CREDENTIAL_BYTES)
      );
      const runnerCredential = capture(
        trustedRead(trustedConfigurationRoot, paths.runnerCredential, 1, MAX_CREDENTIAL_BYTES)
      );
      const assignmentMasterKey = capture(
        trustedRead(
          trustedConfigurationRoot,
          paths.assignmentMasterKey,
          ASSIGNMENT_MASTER_KEY_BYTES,
          ASSIGNMENT_MASTER_KEY_BYTES
        )
      );
      const bootstrapAuthorityPrivateKeyPkcs8 = capture(
        trustedRead(
          trustedConfigurationRoot,
          paths.bootstrapAuthorityPrivateKey,
          1,
          MAX_PRIVATE_KEY_BYTES
        )
      );
      const teamCommandAuthorityPrivateKeyPkcs8 = capture(
        trustedRead(
          trustedConfigurationRoot,
          paths.teamCommandAuthorityPrivateKey,
          1,
          MAX_PRIVATE_KEY_BYTES
        )
      );
      const platformCompensationAuthorityPrivateKeyPkcs8 = capture(
        trustedRead(
          trustedConfigurationRoot,
          paths.platformCompensationAuthorityPrivateKey,
          1,
          MAX_PRIVATE_KEY_BYTES
        )
      );
      const opaqueHandleKey = capture(
        trustedRead(
          trustedConfigurationRoot,
          paths.opaqueHandleKey,
          MIN_OPAQUE_HANDLE_KEY_BYTES,
          MAX_OPAQUE_HANDLE_KEY_BYTES
        )
      );

      assertRawCredential(daytonaApiCredential);
      assertRawCredential(runnerCredential);
      assertNonZeroSecret(assignmentMasterKey);
      assertNonZeroSecret(opaqueHandleKey);
      assertSeparatedPrivateMaterial([
        daytonaApiCredential,
        runnerCredential,
        assignmentMasterKey,
        bootstrapAuthorityPrivateKeyPkcs8,
        teamCommandAuthorityPrivateKeyPkcs8,
        platformCompensationAuthorityPrivateKeyPkcs8,
        opaqueHandleKey,
      ]);

      const privateKeys = [
        validatePrivateIdentity(
          bootstrapAuthorityPrivateKeyPkcs8,
          decoded.identities.bootstrapAuthority
        ),
        validatePrivateIdentity(
          teamCommandAuthorityPrivateKeyPkcs8,
          decoded.identities.teamCommandAuthority
        ),
        validatePrivateIdentity(
          platformCompensationAuthorityPrivateKeyPkcs8,
          decoded.identities.platformCompensationAuthority
        ),
      ] as const;
      const keyIds = privateKeys.map((entry) => entry.keyId);
      const spkiDigests = privateKeys.map((entry) => entry.publicKeySpkiSha256);
      if (
        new Set(keyIds).size !== keyIds.length ||
        new Set(spkiDigests).size !== spkiDigests.length
      ) {
        configurationError("identity-reuse");
      }

      let closed = false;
      const close = Object.freeze(() => {
        if (closed) return;
        closed = true;
        for (const bytes of owned) bytes.fill(0);
      });
      const privateMaterial: ProductionHostedRuntimePrivateMaterial = Object.freeze({
        assignmentMasterKey,
        bootstrapAuthorityPrivateKeyPkcs8,
        teamCommandAuthorityPrivateKeyPkcs8,
        platformCompensationAuthorityPrivateKeyPkcs8,
        daytonaApiCredential,
        runnerCredential,
        opaqueHandleKey,
      });
      return Object.freeze({
        enabled: true as const,
        trustedConfigurationRoot,
        publicConfiguration: decoded,
        privateFiles: Object.freeze({
          bootstrapAuthorityPrivateKey: paths.bootstrapAuthorityPrivateKey,
          teamCommandAuthorityPrivateKey: paths.teamCommandAuthorityPrivateKey,
          platformCompensationAuthorityPrivateKey: paths.platformCompensationAuthorityPrivateKey,
        }),
        privateMaterial,
        close,
      });
    } catch (error) {
      for (const bytes of owned) bytes.fill(0);
      throw error;
    }
  } catch (error) {
    if (error instanceof ProductionHostedRuntimeConfigurationError) throw error;
    configurationError("configuration-unavailable");
  } finally {
    configurationBytes?.fill(0);
  }
  configurationError("configuration-unavailable");
}

/**
 * Register exactly one one-shot hosted factory. The server must pass its
 * concrete Daytona composer explicitly so an enabled deployment can never
 * fall through to LocalTmux or install a partial graph.
 */
export function installConfiguredProductionHostedRuntimeFactory(
  composer?: ProductionHostedRuntimeComposer,
  environment: Readonly<Record<string, string | undefined>> = process.env
): () => void {
  const configuration = loadProductionHostedRuntimeConfiguration(environment);
  if (!configuration.enabled) return Object.freeze(() => undefined);
  if (typeof composer !== "function" || nodeTypes.isProxy(composer)) {
    configuration.close();
    configurationError("composition-unavailable");
  }

  let invoked = false;
  const factory = async (): Promise<DaytonaHostedMultiplayerService> => {
    if (invoked) configurationError("composition-unavailable");
    invoked = true;
    try {
      const service = await composer(configuration);
      if (typeof service !== "object" || service === null || nodeTypes.isProxy(service)) {
        configurationError("composition-unavailable");
      }
      return service;
    } finally {
      configuration.close();
    }
  };

  let uninstall: () => void;
  try {
    uninstall = installHostedMultiplayerServiceFactory(factory);
  } catch {
    configuration.close();
    configurationError("composition-unavailable");
  }
  let uninstalled = false;
  return Object.freeze(() => {
    if (uninstalled) return;
    uninstalled = true;
    try {
      uninstall();
    } finally {
      if (!invoked) configuration.close();
    }
  });
}

function decodePublicConfiguration(bytes: Uint8Array): ProductionHostedRuntimePublicConfiguration {
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    configurationError("invalid-configuration");
  }
  if (!source.endsWith("\n")) configurationError("invalid-configuration");
  const json = source.slice(0, -1);
  let parsed: unknown;
  try {
    parsed = JSON.parse(json) as unknown;
  } catch {
    configurationError("invalid-configuration");
  }
  if (canonicalRuntimeJson(parsed) !== json) configurationError("invalid-configuration");

  const record = exactRecord(parsed, CONFIGURATION_FIELDS);
  if (record.version !== 1 || record.kind !== CONFIGURATION_KIND) {
    configurationError("invalid-configuration");
  }
  const identitiesRecord = exactRecord(record.identities, IDENTITY_FIELDS);
  const bootstrapAuthority = pinnedIdentity(identitiesRecord.bootstrapAuthority);
  const teamCommandAuthority = pinnedIdentity(identitiesRecord.teamCommandAuthority);
  const platformCompensationAuthority = pinnedIdentity(
    identitiesRecord.platformCompensationAuthority
  );
  const settings = exactRecord(record.settings);
  const identities = [bootstrapAuthority, teamCommandAuthority, platformCompensationAuthority];
  if (
    new Set(identities.map((identity) => identity.keyId)).size !== identities.length ||
    new Set(identities.map((identity) => identity.publicKeySpkiSha256)).size !== identities.length
  ) {
    configurationError("identity-reuse");
  }
  return Object.freeze({
    version: 1 as const,
    kind: CONFIGURATION_KIND,
    identities: Object.freeze({
      bootstrapAuthority,
      teamCommandAuthority,
      platformCompensationAuthority,
    }),
    settings: deepFreeze(settings),
    fileSha256: createHash("sha256").update(bytes).digest("hex"),
  });
}

function pinnedIdentity(value: unknown): ProductionHostedRuntimePinnedIdentity {
  const record = exactRecord(value, PINNED_IDENTITY_FIELDS);
  if (typeof record.keyId !== "string" || !KEY_ID.test(record.keyId)) {
    configurationError("invalid-configuration");
  }
  if (
    typeof record.publicKeySpkiPem !== "string" ||
    Buffer.byteLength(record.publicKeySpkiPem, "utf8") > MAX_PUBLIC_KEY_BYTES ||
    record.publicKeySpkiPem.includes("PRIVATE KEY")
  ) {
    configurationError("invalid-configuration");
  }
  let canonicalPem: string;
  let digest: string;
  try {
    const key = createPublicKey(record.publicKeySpkiPem);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
      configurationError("invalid-configuration");
    }
    canonicalPem = key.export({ type: "spki", format: "pem" }).toString();
    digest = createHash("sha256")
      .update(key.export({ type: "spki", format: "der" }))
      .digest("hex");
  } catch (error) {
    if (error instanceof ProductionHostedRuntimeConfigurationError) throw error;
    configurationError("invalid-configuration");
  }
  if (canonicalPem !== record.publicKeySpkiPem) configurationError("invalid-configuration");
  return Object.freeze({
    keyId: record.keyId,
    publicKeySpkiPem: canonicalPem,
    publicKeySpkiSha256: digest,
  });
}

function validatePrivateIdentity(
  bytes: Buffer,
  expected: ProductionHostedRuntimePinnedIdentity
): ProductionHostedRuntimePinnedIdentity {
  try {
    const key = createPrivateKey(bytes);
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
      configurationError("invalid-private-material");
    }
    const canonical = Buffer.from(key.export({ type: "pkcs8", format: "pem" }));
    if (canonical.byteLength !== bytes.byteLength || !timingSafeEqual(canonical, bytes)) {
      configurationError("invalid-private-material");
    }
    const publicDer = createPublicKey(key).export({ type: "spki", format: "der" });
    const expectedPublicDer = createPublicKey(expected.publicKeySpkiPem).export({
      type: "spki",
      format: "der",
    });
    if (
      publicDer.byteLength !== expectedPublicDer.byteLength ||
      !timingSafeEqual(publicDer, expectedPublicDer)
    ) {
      configurationError("invalid-private-material");
    }
    return expected;
  } catch (error) {
    if (error instanceof ProductionHostedRuntimeConfigurationError) throw error;
    configurationError("invalid-private-material");
  }
}

function assertRawCredential(bytes: Buffer): void {
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_CREDENTIAL_BYTES) {
    configurationError("invalid-private-material");
  }
  for (const byte of bytes) {
    if (byte < 0x21 || byte > 0x7e) configurationError("invalid-private-material");
  }
}

function assertNonZeroSecret(bytes: Buffer): void {
  let aggregate = 0;
  for (const byte of bytes) aggregate |= byte;
  if (aggregate === 0) configurationError("invalid-private-material");
}

function assertSeparatedPrivateMaterial(values: readonly Buffer[]): void {
  const digests = values.map((bytes) => createHash("sha256").update(bytes).digest("hex"));
  if (new Set(digests).size !== digests.length) configurationError("identity-reuse");
}

function trustedRead(root: string, filePath: string, minimumBytes: number, maximumBytes: number) {
  try {
    return readTrustedConfigurationFile({
      trustedConfigurationRoot: root,
      filePath,
      minimumBytes,
      maximumBytes,
    });
  } catch {
    configurationError("configuration-unavailable");
  }
}

function requiredCanonicalAbsolutePath(
  environment: Readonly<Record<string, string | undefined>>,
  key: string
): string {
  const value = environmentValue(environment, key);
  if (
    value === undefined ||
    value.length === 0 ||
    value.includes("\0") ||
    !isAbsolute(value) ||
    resolve(value) !== value
  ) {
    configurationError("incomplete-configuration");
  }
  return value;
}

function environmentValue(
  environment: Readonly<Record<string, string | undefined>>,
  key: string
): string | undefined {
  if (typeof environment !== "object" || environment === null || nodeTypes.isProxy(environment)) {
    configurationError("invalid-configuration");
  }
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(environment, key);
  } catch {
    configurationError("invalid-configuration");
  }
  if (descriptor === undefined) return undefined;
  if (
    !("value" in descriptor) ||
    (descriptor.value !== undefined && typeof descriptor.value !== "string")
  ) {
    configurationError("invalid-configuration");
  }
  return descriptor.value as string | undefined;
}

function assertNoUnknownHostedEnvironmentKeys(
  environment: Readonly<Record<string, string | undefined>>
): void {
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(environment);
  } catch {
    configurationError("invalid-configuration");
  }
  for (const key of keys) {
    if (
      typeof key === "string" &&
      key.startsWith(HOSTED_ENVIRONMENT_PREFIX) &&
      !KNOWN_HOSTED_ENVIRONMENT_KEYS.has(key)
    ) {
      configurationError("invalid-configuration");
    }
  }
}

function exactRecord(value: unknown, fields?: ReadonlySet<string>): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    configurationError("invalid-configuration");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    configurationError("invalid-configuration");
  }
  const keys = Reflect.ownKeys(value);
  if (
    (fields !== undefined &&
      (keys.length !== fields.size ||
        keys.some((key) => typeof key !== "string" || !fields.has(key)))) ||
    keys.some((key) => typeof key !== "string")
  ) {
    configurationError("invalid-configuration");
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      configurationError("invalid-configuration");
    }
  }
  return value as Record<string, unknown>;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) configurationError("invalid-configuration");
    deepFreeze(descriptor.value);
  }
  return Object.freeze(value);
}

function configurationError(code: ProductionHostedRuntimeConfigurationErrorCode): never {
  throw new ProductionHostedRuntimeConfigurationError(code);
}
