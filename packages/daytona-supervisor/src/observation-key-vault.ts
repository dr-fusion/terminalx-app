import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, join, normalize } from "node:path";
import { types as nodeTypes } from "node:util";
import type { RuntimeBinding } from "../../../src/lib/team-sessions/contracts";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import {
  createRootFileObservationCredentialResolver,
  type DaytonaSupervisorObservationCredentialRequest,
  type DaytonaSupervisorObservationCredentialResolver,
  type DaytonaSupervisorObservationIssuerLease,
} from "./observation-credential-resolver";
import { DaytonaSupervisorProtocolError } from "./supervisor";

export const DAYTONA_OBSERVATION_KEY_ENVELOPE_KIND =
  "terminalx.daytona-observation-key-envelope" as const;
const PROVISIONING_RECORD_KIND = "terminalx.daytona-observation-key-provisioning" as const;
const METADATA_KIND = "terminalx.daytona-observation-key-vault-entry" as const;
const TOMBSTONE_KIND = "terminalx.daytona-observation-key-retired" as const;
const DIRECTORY_DIGEST_DOMAIN = "terminalx/daytona-observation-key-directory/v1\0";
const BINDING_DIGEST_DOMAIN = "terminalx/daytona-observation-key-binding/v1\0";
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/u;
const MAX_METADATA_BYTES = 64 * 1024;
const MAX_PRIVATE_KEY_BYTES = 64 * 1024;
const MAX_ENVELOPE_BYTES = MAX_METADATA_BYTES + MAX_PRIVATE_KEY_BYTES + 4;
const ENTRY_FILES = Object.freeze(["metadata.json", "observation-key.pk8", "provisioning.json"]);

export interface DaytonaObservationKeyEnvelopeMetadata {
  readonly version: 1;
  readonly kind: typeof DAYTONA_OBSERVATION_KEY_ENVELOPE_KIND;
  readonly keyProvisioningRef: string;
  readonly binding: RuntimeBinding;
  readonly issuerKeyId: string;
  readonly publicKeySpkiPem: string;
  readonly privateKeyBytes: number;
  readonly notAfterMs: number;
}

export interface DaytonaObservationKeyPublicDescriptor {
  readonly keyProvisioningRef: string;
  readonly issuerKeyId: string;
  readonly publicKeySpkiPem: string;
  readonly bindingDigest: string;
  readonly notAfterMs: number;
}

export interface DaytonaObservationKeyRetirementRequest {
  readonly keyProvisioningRef: string;
  readonly binding: RuntimeBinding;
}

export interface CreateRootObservationKeyVaultOptions {
  /** Root-owned 0700 tmpfs or checkpoint-excluded directory. */
  readonly vaultRoot: string;
  readonly expectedOwnerUid?: number;
  readonly observationTtlMs?: number;
  readonly clock?: () => number;
}

export interface RootObservationKeyVault extends DaytonaSupervisorObservationCredentialResolver {
  /** Takes ownership of `envelope`; every byte is zeroed on success or failure. */
  provision(envelope: Buffer): Promise<DaytonaObservationKeyPublicDescriptor>;
  /** Exact-binding, no-active-lease retirement followed by secret-file deletion. */
  retire(request: DaytonaObservationKeyRetirementRequest): Promise<void>;
  close(): Promise<void>;
}

/**
 * Binary format: uint32be metadata length, canonical JSON metadata, raw
 * canonical Ed25519 PKCS#8 DER. Private bytes are never represented as a JS
 * string, environment variable, provider label, protocol frame or plan.
 */
export function encodeDaytonaObservationKeyEnvelope(
  unsafeMetadata: DaytonaObservationKeyEnvelopeMetadata,
  privateKeyPkcs8Der: Buffer
): Buffer {
  const metadata = snapshotEnvelopeMetadata(unsafeMetadata);
  if (
    !Buffer.isBuffer(privateKeyPkcs8Der) ||
    privateKeyPkcs8Der.byteLength !== metadata.privateKeyBytes
  ) {
    throw new TypeError();
  }
  const metadataBytes = Buffer.from(canonicalRuntimeJson(metadata), "utf8");
  if (metadataBytes.byteLength < 2 || metadataBytes.byteLength > MAX_METADATA_BYTES) {
    metadataBytes.fill(0);
    throw new TypeError();
  }
  const result = Buffer.allocUnsafe(4 + metadataBytes.byteLength + privateKeyPkcs8Der.byteLength);
  result.writeUInt32BE(metadataBytes.byteLength, 0);
  metadataBytes.copy(result, 4);
  privateKeyPkcs8Der.copy(result, 4 + metadataBytes.byteLength);
  metadataBytes.fill(0);
  return result;
}

export function createRootObservationKeyVault(
  unsafeOptions: CreateRootObservationKeyVaultOptions
): RootObservationKeyVault {
  return new RootFileObservationKeyVault(unsafeOptions);
}

class RootFileObservationKeyVault implements RootObservationKeyVault {
  private readonly options: CapturedOptions;
  private readonly activeLeases = new Map<string, number>();
  private closed = false;
  private operation = Promise.resolve();

  constructor(unsafeOptions: CreateRootObservationKeyVaultOptions) {
    this.options = captureOptions(unsafeOptions);
    assertVaultRoot(this.options);
    ensureTombstoneDirectory(this.options);
  }

  provision(envelope: Buffer): Promise<DaytonaObservationKeyPublicDescriptor> {
    return this.exclusive(async () => this.provisionExclusive(envelope));
  }

  async resolve(
    unsafeRequest: DaytonaSupervisorObservationCredentialRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorObservationIssuerLease> {
    const request = snapshotRequest(unsafeRequest);
    if (!(signal instanceof AbortSignal) || signal.aborted) {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    const entry = await this.exclusive(async () => {
      this.assertOpen();
      assertVaultRoot(this.options);
      const loaded = readEntry(this.options, request.keyProvisioningRef);
      if (
        loaded.metadata.notAfterMs <= sampleClock(this.options.clock) ||
        canonicalRuntimeJson(loaded.metadata.binding) !== canonicalRuntimeJson(request.binding) ||
        loaded.metadata.issuerKeyId !== request.issuerKeyId ||
        loaded.metadata.publicKeySpkiPem !== request.publicKeySpkiPem
      ) {
        throw new DaytonaSupervisorProtocolError("not-ready");
      }
      const count = this.activeLeases.get(loaded.directoryDigest) ?? 0;
      this.activeLeases.set(loaded.directoryDigest, count + 1);
      return loaded;
    });

    let lease: DaytonaSupervisorObservationIssuerLease;
    try {
      const resolver = createRootFileObservationCredentialResolver({
        trustedConfigurationRoot: this.options.vaultRoot,
        provisioningRecordFile: join(entry.directory, "provisioning.json"),
        observationTtlMs: this.options.observationTtlMs,
        clock: this.options.clock,
      });
      lease = await resolver.resolve(request, signal);
    } catch (error) {
      await this.release(entry.directoryDigest);
      throw error;
    }
    let active = true;
    return Object.freeze({
      lifecycleObservationIssuer: lease.lifecycleObservationIssuer,
      compensationObservationIssuer: lease.compensationObservationIssuer,
      close: async (): Promise<void> => {
        if (!active) return;
        active = false;
        await lease.close().catch(() => undefined);
        await this.release(entry.directoryDigest);
      },
    });
  }

  retire(unsafeRequest: DaytonaObservationKeyRetirementRequest): Promise<void> {
    return this.exclusive(async () => {
      this.assertOpen();
      const request = snapshotRetirementRequest(unsafeRequest);
      assertVaultRoot(this.options);
      const expectedDirectoryDigest = directoryDigest(request.keyProvisioningRef);
      const expectedDirectory = join(this.options.vaultRoot, expectedDirectoryDigest);
      if (!existsSync(expectedDirectory)) {
        assertMatchingTombstone(
          this.options,
          expectedDirectoryDigest,
          bindingDigest(request.binding)
        );
        return;
      }
      const entry = readEntry(this.options, request.keyProvisioningRef);
      if (
        canonicalRuntimeJson(entry.metadata.binding) !== canonicalRuntimeJson(request.binding) ||
        (this.activeLeases.get(entry.directoryDigest) ?? 0) !== 0
      ) {
        throw new DaytonaSupervisorProtocolError("conflict");
      }
      writeTombstone(this.options, entry.metadata, entry.directoryDigest);
      deleteExactEntry(entry);
    });
  }

  async close(): Promise<void> {
    await this.exclusive(async () => {
      if (this.activeLeases.size !== 0) throw new DaytonaSupervisorProtocolError("conflict");
      this.closed = true;
    });
  }

  private async provisionExclusive(
    envelope: Buffer
  ): Promise<DaytonaObservationKeyPublicDescriptor> {
    if (!Buffer.isBuffer(envelope)) throw new DaytonaSupervisorProtocolError("invalid-request");
    try {
      this.assertOpen();
      assertVaultRoot(this.options);
      const decoded = decodeEnvelope(envelope);
      if (decoded.metadata.notAfterMs <= sampleClock(this.options.clock)) {
        throw new DaytonaSupervisorProtocolError("invalid-request");
      }
      const directoryDigestValue = directoryDigest(decoded.metadata.keyProvisioningRef);
      const finalDirectory = join(this.options.vaultRoot, directoryDigestValue);
      const tombstone = tombstonePath(this.options, directoryDigestValue);
      if (existsSync(finalDirectory) || existsSync(tombstone)) {
        throw new DaytonaSupervisorProtocolError("conflict");
      }
      const temporaryDirectory = join(
        this.options.vaultRoot,
        `.provision-${directoryDigestValue}-${randomBytes(12).toString("hex")}`
      );
      mkdirSync(temporaryDirectory, { mode: 0o700 });
      chmodSync(temporaryDirectory, 0o700);
      try {
        const privateKeyFile = join(temporaryDirectory, "observation-key.pk8");
        writeExclusiveFile(privateKeyFile, decoded.privateKey, 0o600);
        const provisioning = Object.freeze({
          version: 1,
          kind: PROVISIONING_RECORD_KIND,
          keyProvisioningRef: decoded.metadata.keyProvisioningRef,
          binding: decoded.metadata.binding,
          issuerKeyId: decoded.metadata.issuerKeyId,
          publicKeySpkiPem: decoded.metadata.publicKeySpkiPem,
          privateKeyFile,
        });
        // The final absolute private path is not known until rename. Write the
        // canonical final path, never the temporary path.
        const finalProvisioning = Object.freeze({
          ...provisioning,
          privateKeyFile: join(finalDirectory, "observation-key.pk8"),
        });
        writeExclusiveJson(join(temporaryDirectory, "provisioning.json"), finalProvisioning);
        writeExclusiveJson(
          join(temporaryDirectory, "metadata.json"),
          Object.freeze({
            version: 1,
            kind: METADATA_KIND,
            keyProvisioningRef: decoded.metadata.keyProvisioningRef,
            binding: decoded.metadata.binding,
            issuerKeyId: decoded.metadata.issuerKeyId,
            publicKeySpkiPem: decoded.metadata.publicKeySpkiPem,
            bindingDigest: bindingDigest(decoded.metadata.binding),
            notAfterMs: decoded.metadata.notAfterMs,
          })
        );
        renameSync(temporaryDirectory, finalDirectory);
        fsyncDirectory(this.options.vaultRoot);
      } catch (error) {
        deleteTemporaryEntry(temporaryDirectory);
        throw error;
      } finally {
        decoded.privateKey.fill(0);
      }
      return Object.freeze({
        keyProvisioningRef: decoded.metadata.keyProvisioningRef,
        issuerKeyId: decoded.metadata.issuerKeyId,
        publicKeySpkiPem: decoded.metadata.publicKeySpkiPem,
        bindingDigest: bindingDigest(decoded.metadata.binding),
        notAfterMs: decoded.metadata.notAfterMs,
      });
    } catch (error) {
      if (error instanceof DaytonaSupervisorProtocolError) throw error;
      throw new DaytonaSupervisorProtocolError("not-ready");
    } finally {
      envelope.fill(0);
    }
  }

  private release(directoryDigestValue: string): Promise<void> {
    return this.exclusive(async () => {
      const count = this.activeLeases.get(directoryDigestValue);
      if (count === undefined) return;
      if (count <= 1) this.activeLeases.delete(directoryDigestValue);
      else this.activeLeases.set(directoryDigestValue, count - 1);
    });
  }

  private exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.operation.then(operation, operation);
    this.operation = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  private assertOpen(): void {
    if (this.closed) throw new DaytonaSupervisorProtocolError("unavailable");
  }
}

interface CapturedOptions {
  readonly vaultRoot: string;
  readonly expectedOwnerUid: number;
  readonly observationTtlMs: number;
  readonly clock: () => number;
}

interface VaultMetadata {
  readonly version: 1;
  readonly kind: typeof METADATA_KIND;
  readonly keyProvisioningRef: string;
  readonly binding: RuntimeBinding;
  readonly issuerKeyId: string;
  readonly publicKeySpkiPem: string;
  readonly bindingDigest: string;
  readonly notAfterMs: number;
}

interface LoadedEntry {
  readonly directory: string;
  readonly directoryDigest: string;
  readonly metadata: VaultMetadata;
}

function captureOptions(value: CreateRootObservationKeyVaultOptions): CapturedOptions {
  if (
    typeof value !== "object" ||
    value === null ||
    nodeTypes.isProxy(value) ||
    typeof value.vaultRoot !== "string" ||
    !isAbsolute(value.vaultRoot) ||
    normalize(value.vaultRoot) !== value.vaultRoot
  ) {
    throw new TypeError();
  }
  const expectedOwnerUid = value.expectedOwnerUid ?? 0;
  const observationTtlMs = value.observationTtlMs ?? 5 * 60_000;
  if (
    !Number.isSafeInteger(expectedOwnerUid) ||
    expectedOwnerUid < 0 ||
    !Number.isSafeInteger(observationTtlMs) ||
    observationTtlMs < 1 ||
    observationTtlMs > 10 * 60_000 ||
    (value.clock !== undefined && typeof value.clock !== "function")
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    vaultRoot: value.vaultRoot,
    expectedOwnerUid,
    observationTtlMs,
    clock: value.clock ?? Date.now,
  });
}

function decodeEnvelope(envelope: Buffer): {
  readonly metadata: DaytonaObservationKeyEnvelopeMetadata;
  readonly privateKey: Buffer;
} {
  if (envelope.byteLength < 6 || envelope.byteLength > MAX_ENVELOPE_BYTES) throw new TypeError();
  const metadataLength = envelope.readUInt32BE(0);
  if (metadataLength < 2 || metadataLength > MAX_METADATA_BYTES) throw new TypeError();
  const privateOffset = 4 + metadataLength;
  if (privateOffset >= envelope.byteLength) throw new TypeError();
  const metadataBytes = Buffer.from(envelope.subarray(4, privateOffset));
  let metadata: DaytonaObservationKeyEnvelopeMetadata;
  try {
    metadata = snapshotEnvelopeMetadata(JSON.parse(metadataBytes.toString("utf8")));
  } finally {
    metadataBytes.fill(0);
  }
  if (envelope.byteLength - privateOffset !== metadata.privateKeyBytes) throw new TypeError();
  const privateKey = Buffer.from(envelope.subarray(privateOffset));
  try {
    const key = createPrivateKey({ key: privateKey, format: "der", type: "pkcs8" });
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") throw new TypeError();
    const canonicalPrivate = key.export({ format: "der", type: "pkcs8" });
    const canonicalPrivateBytes = Buffer.isBuffer(canonicalPrivate)
      ? canonicalPrivate
      : Buffer.from(canonicalPrivate);
    try {
      if (
        canonicalPrivateBytes.byteLength !== privateKey.byteLength ||
        !timingSafeEqual(canonicalPrivateBytes, privateKey)
      ) {
        throw new TypeError();
      }
    } finally {
      canonicalPrivateBytes.fill(0);
    }
    const publicPem = createPublicKey(key).export({ type: "spki", format: "pem" });
    if (publicPem !== metadata.publicKeySpkiPem) throw new TypeError();
    return Object.freeze({ metadata, privateKey });
  } catch {
    privateKey.fill(0);
    throw new TypeError();
  }
}

function snapshotEnvelopeMetadata(value: unknown): DaytonaObservationKeyEnvelopeMetadata {
  const record = exactRecord(value, [
    "version",
    "kind",
    "keyProvisioningRef",
    "binding",
    "issuerKeyId",
    "publicKeySpkiPem",
    "privateKeyBytes",
    "notAfterMs",
  ]);
  if (
    field(record, "version") !== 1 ||
    field(record, "kind") !== DAYTONA_OBSERVATION_KEY_ENVELOPE_KIND
  ) {
    throw new TypeError();
  }
  const privateKeyBytes = positiveInteger(field(record, "privateKeyBytes"));
  if (privateKeyBytes > MAX_PRIVATE_KEY_BYTES) throw new TypeError();
  return Object.freeze({
    version: 1,
    kind: DAYTONA_OBSERVATION_KEY_ENVELOPE_KIND,
    keyProvisioningRef: safeReference(field(record, "keyProvisioningRef")),
    binding: snapshotBinding(field(record, "binding")),
    issuerKeyId: safeReference(field(record, "issuerKeyId")),
    publicKeySpkiPem: canonicalPublicKeyPem(field(record, "publicKeySpkiPem")),
    privateKeyBytes,
    notAfterMs: positiveInteger(field(record, "notAfterMs")),
  });
}

function snapshotRequest(
  value: DaytonaSupervisorObservationCredentialRequest
): DaytonaSupervisorObservationCredentialRequest {
  const record = exactRecord(value, [
    "keyProvisioningRef",
    "binding",
    "issuerKeyId",
    "publicKeySpkiPem",
  ]);
  return Object.freeze({
    keyProvisioningRef: safeReference(field(record, "keyProvisioningRef")),
    binding: snapshotBinding(field(record, "binding")),
    issuerKeyId: safeReference(field(record, "issuerKeyId")),
    publicKeySpkiPem: canonicalPublicKeyPem(field(record, "publicKeySpkiPem")),
  });
}

function snapshotRetirementRequest(
  value: DaytonaObservationKeyRetirementRequest
): DaytonaObservationKeyRetirementRequest {
  const record = exactRecord(value, ["keyProvisioningRef", "binding"]);
  return Object.freeze({
    keyProvisioningRef: safeReference(field(record, "keyProvisioningRef")),
    binding: snapshotBinding(field(record, "binding")),
  });
}

function readEntry(options: CapturedOptions, keyProvisioningRef: string): LoadedEntry {
  const digest = directoryDigest(keyProvisioningRef);
  const directory = join(options.vaultRoot, digest);
  const metadataFile = join(directory, "metadata.json");
  try {
    assertEntryDirectory(options, directory);
    const bytes = readFileSync(metadataFile);
    if (bytes.byteLength < 2 || bytes.byteLength > MAX_METADATA_BYTES) throw new TypeError();
    try {
      const record = exactRecord(JSON.parse(bytes.toString("utf8")), [
        "version",
        "kind",
        "keyProvisioningRef",
        "binding",
        "issuerKeyId",
        "publicKeySpkiPem",
        "bindingDigest",
        "notAfterMs",
      ]);
      if (field(record, "version") !== 1 || field(record, "kind") !== METADATA_KIND) {
        throw new TypeError();
      }
      const binding = snapshotBinding(field(record, "binding"));
      const metadata = Object.freeze({
        version: 1 as const,
        kind: METADATA_KIND,
        keyProvisioningRef: safeReference(field(record, "keyProvisioningRef")),
        binding,
        issuerKeyId: safeReference(field(record, "issuerKeyId")),
        publicKeySpkiPem: canonicalPublicKeyPem(field(record, "publicKeySpkiPem")),
        bindingDigest: digestValue(field(record, "bindingDigest")),
        notAfterMs: positiveInteger(field(record, "notAfterMs")),
      });
      if (
        metadata.keyProvisioningRef !== keyProvisioningRef ||
        metadata.bindingDigest !== bindingDigest(binding)
      ) {
        throw new TypeError();
      }
      return Object.freeze({ directory, directoryDigest: digest, metadata });
    } finally {
      bytes.fill(0);
    }
  } catch (error) {
    if (error instanceof DaytonaSupervisorProtocolError) throw error;
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

function assertVaultRoot(options: CapturedOptions): void {
  if (typeof process.geteuid !== "function" || process.geteuid() !== options.expectedOwnerUid) {
    throw new DaytonaSupervisorProtocolError("permission-denied");
  }
  const stat = lstatSync(options.vaultRoot);
  if (
    realpathSync.native(options.vaultRoot) !== options.vaultRoot ||
    stat.isSymbolicLink() ||
    !stat.isDirectory() ||
    stat.uid !== options.expectedOwnerUid ||
    (stat.mode & 0o777) !== 0o700
  ) {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

function assertEntryDirectory(options: CapturedOptions, directory: string): void {
  const stat = lstatSync(directory);
  if (
    realpathSync.native(directory) !== directory ||
    stat.isSymbolicLink() ||
    !stat.isDirectory() ||
    stat.uid !== options.expectedOwnerUid ||
    (stat.mode & 0o777) !== 0o700 ||
    canonicalRuntimeJson(readdirSync(directory).sort()) !== canonicalRuntimeJson(ENTRY_FILES)
  ) {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
  for (const name of ENTRY_FILES) {
    const child = lstatSync(join(directory, name));
    if (
      child.isSymbolicLink() ||
      !child.isFile() ||
      child.nlink !== 1 ||
      child.uid !== options.expectedOwnerUid ||
      (child.mode & 0o777) !== 0o600
    ) {
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
  }
}

function ensureTombstoneDirectory(options: CapturedOptions): void {
  const directory = join(options.vaultRoot, ".retired");
  if (!existsSync(directory)) mkdirSync(directory, { mode: 0o700 });
  chmodSync(directory, 0o700);
  const stat = lstatSync(directory);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== options.expectedOwnerUid ||
    (stat.mode & 0o777) !== 0o700
  ) {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

function writeTombstone(
  options: CapturedOptions,
  metadata: VaultMetadata,
  directoryDigestValue: string
): void {
  const path = tombstonePath(options, directoryDigestValue);
  if (existsSync(path)) {
    assertMatchingTombstone(options, directoryDigestValue, metadata.bindingDigest);
    return;
  }
  writeExclusiveJson(
    path,
    Object.freeze({
      version: 1,
      kind: TOMBSTONE_KIND,
      directoryDigest: directoryDigestValue,
      bindingDigest: metadata.bindingDigest,
      issuerKeyId: metadata.issuerKeyId,
      retiredAtMs: sampleClock(options.clock),
    })
  );
  fsyncDirectory(join(options.vaultRoot, ".retired"));
}

function assertMatchingTombstone(
  options: CapturedOptions,
  directoryDigestValue: string,
  expectedBindingDigest: string
): void {
  const path = tombstonePath(options, directoryDigestValue);
  try {
    const stat = lstatSync(path);
    if (
      stat.isSymbolicLink() ||
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.uid !== options.expectedOwnerUid ||
      (stat.mode & 0o777) !== 0o600 ||
      stat.size < 2 ||
      stat.size > MAX_METADATA_BYTES
    ) {
      throw new TypeError();
    }
    const bytes = readFileSync(path);
    try {
      const record = exactRecord(JSON.parse(bytes.toString("utf8")), [
        "version",
        "kind",
        "directoryDigest",
        "bindingDigest",
        "issuerKeyId",
        "retiredAtMs",
      ]);
      if (
        field(record, "version") !== 1 ||
        field(record, "kind") !== TOMBSTONE_KIND ||
        digestValue(field(record, "directoryDigest")) !== directoryDigestValue ||
        digestValue(field(record, "bindingDigest")) !== expectedBindingDigest
      ) {
        throw new TypeError();
      }
      safeReference(field(record, "issuerKeyId"));
      positiveInteger(field(record, "retiredAtMs"));
    } finally {
      bytes.fill(0);
    }
  } catch {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

function tombstonePath(options: CapturedOptions, directoryDigestValue: string): string {
  return join(options.vaultRoot, ".retired", `${directoryDigestValue}.json`);
}

function deleteExactEntry(entry: LoadedEntry): void {
  assertOnlyEntryFiles(entry.directory);
  for (const name of ENTRY_FILES) unlinkSync(join(entry.directory, name));
  rmdirSync(entry.directory);
}

function deleteTemporaryEntry(directory: string): void {
  if (!existsSync(directory)) return;
  const names = readdirSync(directory);
  if (names.some((name) => !ENTRY_FILES.includes(name))) return;
  for (const name of names) {
    const path = join(directory, name);
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) return;
    unlinkSync(path);
  }
  rmdirSync(directory);
}

function assertOnlyEntryFiles(directory: string): void {
  const names = readdirSync(directory).sort();
  if (canonicalRuntimeJson(names) !== canonicalRuntimeJson(ENTRY_FILES)) {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

function writeExclusiveJson(path: string, value: unknown): void {
  const bytes = Buffer.from(`${canonicalRuntimeJson(value)}\n`, "utf8");
  try {
    writeExclusiveFile(path, bytes, 0o600);
  } finally {
    bytes.fill(0);
  }
}

function writeExclusiveFile(path: string, bytes: Buffer, mode: number): void {
  let descriptor = -1;
  try {
    descriptor = openSync(
      path,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
      mode
    );
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
  chmodSync(path, mode);
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, fsConstants.O_RDONLY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "runtimeAssignmentGeneration",
    "sandboxId",
    "sandboxGeneration",
    "runtimePrincipalId",
  ]);
  return Object.freeze({
    teamId: safeReference(field(record, "teamId")),
    projectId: safeReference(field(record, "projectId")),
    sessionId: safeReference(field(record, "sessionId")),
    runtimeAssignmentId: safeReference(field(record, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(field(record, "runtimeAssignmentGeneration")),
    sandboxId: safeReference(field(record, "sandboxId")),
    sandboxGeneration: positiveInteger(field(record, "sandboxGeneration")),
    runtimePrincipalId: safeReference(field(record, "runtimePrincipalId")),
  });
}

function canonicalPublicKeyPem(value: unknown): string {
  if (typeof value !== "string") throw new TypeError();
  const key = createPublicKey(value);
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError();
  const canonical = key.export({ type: "spki", format: "pem" });
  if (typeof canonical !== "string" || canonical !== value) throw new TypeError();
  return value;
}

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw new TypeError();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of names) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) throw new TypeError();
  return value;
}

function digestValue(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new TypeError();
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new TypeError();
  return value as number;
}

function directoryDigest(keyProvisioningRef: string): string {
  return createHash("sha256")
    .update(DIRECTORY_DIGEST_DOMAIN, "utf8")
    .update(keyProvisioningRef, "utf8")
    .digest("hex");
}

function bindingDigest(binding: RuntimeBinding): string {
  return createHash("sha256")
    .update(BINDING_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson(binding), "utf8")
    .digest("hex");
}

function sampleClock(clock: () => number): number {
  const value = clock();
  if (!Number.isSafeInteger(value) || value < 0)
    throw new DaytonaSupervisorProtocolError("not-ready");
  return value;
}
