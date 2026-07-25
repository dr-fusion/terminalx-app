import {
  createHash,
  createPublicKey,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { basename, dirname, isAbsolute, join, normalize, resolve } from "node:path";
import { types as nodeTypes } from "node:util";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import {
  DAYTONA_SUPERVISOR_STATE_SIGNATURE_DOMAIN,
  DaytonaSupervisorProtocolError,
  type DaytonaSupervisorState,
  type DaytonaSupervisorStateStore,
} from "./supervisor";

const STATE_ENVELOPE_KIND = "terminalx.daytona-supervisor-state" as const;
const SHA256 = /^[0-9a-f]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const SAFE_FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DEFAULT_MAX_STATE_BYTES = 64 * 1024 * 1024;
const MIN_MAX_STATE_BYTES = 4096;
const MAX_MAX_STATE_BYTES = 256 * 1024 * 1024;

interface SignedStateEnvelope {
  readonly version: 1;
  readonly kind: typeof STATE_ENVELOPE_KIND;
  readonly payloadDigest: string;
  readonly payload: DaytonaSupervisorState;
  readonly authority: {
    readonly algorithm: "ed25519";
    readonly signature: string;
  };
}

export interface CreateSignedDaytonaSupervisorStateStoreOptions {
  /** Existing canonical 0700 directory owned by `expectedOwnerUid`. */
  readonly stateDirectory: string;
  readonly stateFileName?: string;
  readonly signingPrivateKey: KeyObject;
  readonly verificationPublicKey: KeyObject;
  readonly expectedOwnerUid: number;
  readonly maxStateBytes?: number;
}

/**
 * A single-writer, signed and atomically replaced supervisor WAL. The caller is
 * responsible for keeping the signing key outside the agent/toolbox uid.
 */
export function createSignedDaytonaSupervisorStateStore(
  unsafeOptions: CreateSignedDaytonaSupervisorStateStoreOptions
): DaytonaSupervisorStateStore {
  const options = captureOptions(unsafeOptions);
  verifyDirectory(options);
  let loadedConfigurationDigest: string | null = null;

  return Object.freeze({
    load(configurationDigest: string): DaytonaSupervisorState {
      verifyDirectory(options);
      const expectedConfigurationDigest = requiredDigest(configurationDigest);
      if (
        loadedConfigurationDigest !== null &&
        !sameDigest(loadedConfigurationDigest, expectedConfigurationDigest)
      ) {
        throw new DaytonaSupervisorProtocolError("not-ready");
      }
      if (!existsSync(options.stateFile)) {
        const initial = Object.freeze({
          version: 1,
          configurationDigest: expectedConfigurationDigest,
          nextCursor: 1,
          operations: Object.freeze([]),
        });
        loadedConfigurationDigest = expectedConfigurationDigest;
        return initial;
      }
      let serialized: Buffer;
      let descriptor = -1;
      try {
        verifyPrivateRegularFile(
          options.stateFile,
          options.expectedOwnerUid,
          options.maxStateBytes
        );
        descriptor = openSync(options.stateFile, fsConstants.O_RDONLY | noFollowFlag());
        const stat = fstatSync(descriptor);
        requirePrivateRegularStat(stat, options.expectedOwnerUid, options.maxStateBytes);
        serialized = readFileSync(descriptor);
      } catch {
        throw new DaytonaSupervisorProtocolError("not-ready");
      } finally {
        if (descriptor >= 0) closeSync(descriptor);
      }
      if (serialized.byteLength > options.maxStateBytes) {
        throw new DaytonaSupervisorProtocolError("not-ready");
      }
      const state = verifyEnvelope(
        serialized,
        expectedConfigurationDigest,
        options.verificationPublicKey
      );
      loadedConfigurationDigest = expectedConfigurationDigest;
      return state;
    },

    async commit(state: DaytonaSupervisorState): Promise<void> {
      verifyDirectory(options);
      let envelope: SignedStateEnvelope;
      let serialized: Buffer;
      try {
        const payload = snapshotRuntimeSupervisorPortableData(state) as DaytonaSupervisorState;
        const stateConfigurationDigest = requiredDigest(payload.configurationDigest);
        if (
          loadedConfigurationDigest === null ||
          !sameDigest(loadedConfigurationDigest, stateConfigurationDigest)
        ) {
          throw new DaytonaSupervisorProtocolError("not-ready");
        }
        const payloadJson = canonicalRuntimeJson(payload);
        const payloadDigest = sha256(payloadJson);
        const signature = sign(
          null,
          Buffer.from(`${DAYTONA_SUPERVISOR_STATE_SIGNATURE_DOMAIN}${payloadJson}`, "utf8"),
          options.signingPrivateKey
        ).toString("base64url");
        if (!SIGNATURE.test(signature)) throw new TypeError();
        envelope = Object.freeze({
          version: 1,
          kind: STATE_ENVELOPE_KIND,
          payloadDigest,
          payload,
          authority: Object.freeze({ algorithm: "ed25519", signature }),
        });
        serialized = Buffer.from(`${canonicalRuntimeJson(envelope)}\n`, "utf8");
      } catch (error) {
        if (error instanceof DaytonaSupervisorProtocolError) throw error;
        throw new DaytonaSupervisorProtocolError("unavailable");
      }
      if (serialized.byteLength > options.maxStateBytes) {
        throw new DaytonaSupervisorProtocolError("not-ready");
      }

      const temporaryFile = join(
        options.stateDirectory,
        `.${options.stateFileName}.${randomBytes(16).toString("hex")}.tmp`
      );
      let descriptor = -1;
      try {
        descriptor = openSync(
          temporaryFile,
          fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollowFlag(),
          0o600
        );
        const stat = fstatSync(descriptor);
        requirePrivateRegularStat(stat, options.expectedOwnerUid, options.maxStateBytes);
        writeFileSync(descriptor, serialized);
        fsyncSync(descriptor);
        closeSync(descriptor);
        descriptor = -1;
        verifyDirectory(options);
        renameSync(temporaryFile, options.stateFile);
        fsyncDirectory(options.stateDirectory);
        verifyPrivateRegularFile(
          options.stateFile,
          options.expectedOwnerUid,
          options.maxStateBytes
        );
      } catch {
        if (descriptor >= 0) closeSync(descriptor);
        try {
          unlinkSync(temporaryFile);
        } catch {
          // The atomic rename may already have consumed the temporary file.
        }
        throw new DaytonaSupervisorProtocolError("unavailable");
      }
    },
  });
}

function captureOptions(value: CreateSignedDaytonaSupervisorStateStoreOptions): Readonly<{
  stateDirectory: string;
  stateFileName: string;
  stateFile: string;
  signingPrivateKey: KeyObject;
  verificationPublicKey: KeyObject;
  expectedOwnerUid: number;
  maxStateBytes: number;
}> {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value)) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  const stateDirectory = canonicalAbsolutePath(value.stateDirectory);
  const stateFileName = value.stateFileName ?? "state.json";
  if (
    typeof stateFileName !== "string" ||
    !SAFE_FILE_NAME.test(stateFileName) ||
    basename(stateFileName) !== stateFileName
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  if (!Number.isSafeInteger(value.expectedOwnerUid) || value.expectedOwnerUid < 0) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  const maxStateBytes = value.maxStateBytes ?? DEFAULT_MAX_STATE_BYTES;
  if (
    !Number.isSafeInteger(maxStateBytes) ||
    maxStateBytes < MIN_MAX_STATE_BYTES ||
    maxStateBytes > MAX_MAX_STATE_BYTES
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  assertEd25519PrivateKey(value.signingPrivateKey);
  assertEd25519PublicKey(value.verificationPublicKey);
  const derivedPublicKey = createPublicKey(value.signingPrivateKey);
  if (!samePublicKey(derivedPublicKey, value.verificationPublicKey)) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  const stateFile = resolve(stateDirectory, stateFileName);
  if (dirname(stateFile) !== stateDirectory) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return Object.freeze({
    stateDirectory,
    stateFileName,
    stateFile,
    signingPrivateKey: value.signingPrivateKey,
    verificationPublicKey: value.verificationPublicKey,
    expectedOwnerUid: value.expectedOwnerUid,
    maxStateBytes,
  });
}

function verifyEnvelope(
  bytes: Buffer,
  expectedConfigurationDigest: string,
  publicKey: KeyObject
): DaytonaSupervisorState {
  try {
    const parsed = snapshotRuntimeSupervisorPortableData(JSON.parse(bytes.toString("utf8")));
    const envelope = exactRecord(parsed, [
      "version",
      "kind",
      "payloadDigest",
      "payload",
      "authority",
    ]);
    if (field(envelope, "version") !== 1 || field(envelope, "kind") !== STATE_ENVELOPE_KIND) {
      throw new TypeError();
    }
    const payloadDigest = requiredDigest(field(envelope, "payloadDigest"));
    const payload = field(envelope, "payload") as DaytonaSupervisorState;
    const payloadJson = canonicalRuntimeJson(payload);
    if (!sameDigest(payloadDigest, sha256(payloadJson))) throw new TypeError();
    const authority = exactRecord(field(envelope, "authority"), ["algorithm", "signature"]);
    if (field(authority, "algorithm") !== "ed25519") throw new TypeError();
    const signature = field(authority, "signature");
    if (typeof signature !== "string" || !SIGNATURE.test(signature)) throw new TypeError();
    const valid = verify(
      null,
      Buffer.from(`${DAYTONA_SUPERVISOR_STATE_SIGNATURE_DOMAIN}${payloadJson}`, "utf8"),
      publicKey,
      Buffer.from(signature, "base64url")
    );
    if (!valid) throw new TypeError();
    const record = exactRecord(payload, [
      "version",
      "configurationDigest",
      "nextCursor",
      "operations",
    ]);
    if (
      field(record, "version") !== 1 ||
      !sameDigest(requiredDigest(field(record, "configurationDigest")), expectedConfigurationDigest)
    ) {
      throw new TypeError();
    }
    return payload;
  } catch {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

function verifyDirectory(options: {
  readonly stateDirectory: string;
  readonly expectedOwnerUid: number;
}): void {
  try {
    if (realpathSync(options.stateDirectory) !== options.stateDirectory) throw new TypeError();
    const stat = lstatSync(options.stateDirectory);
    if (
      stat.isSymbolicLink() ||
      !stat.isDirectory() ||
      stat.uid !== options.expectedOwnerUid ||
      (stat.mode & 0o077) !== 0
    ) {
      throw new TypeError();
    }
  } catch {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

function verifyPrivateRegularFile(path: string, expectedOwnerUid: number, maxBytes: number): void {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) throw new TypeError();
  requirePrivateRegularStat(stat, expectedOwnerUid, maxBytes);
}

function requirePrivateRegularStat(stat: Stats, expectedOwnerUid: number, maxBytes: number): void {
  if (
    !stat.isFile() ||
    stat.nlink !== 1 ||
    stat.uid !== expectedOwnerUid ||
    (stat.mode & 0o077) !== 0 ||
    stat.size > maxBytes
  ) {
    throw new TypeError();
  }
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, fsConstants.O_RDONLY | directoryFlag() | noFollowFlag());
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function canonicalAbsolutePath(value: unknown): string {
  if (typeof value !== "string" || !isAbsolute(value) || normalize(value) !== value) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return value;
}

function assertEd25519PrivateKey(value: unknown): asserts value is KeyObject {
  if (
    !(value instanceof Object) ||
    nodeTypes.isProxy(value) ||
    (value as KeyObject).type !== "private" ||
    (value as KeyObject).asymmetricKeyType !== "ed25519"
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
}

function assertEd25519PublicKey(value: unknown): asserts value is KeyObject {
  if (
    !(value instanceof Object) ||
    nodeTypes.isProxy(value) ||
    (value as KeyObject).type !== "public" ||
    (value as KeyObject).asymmetricKeyType !== "ed25519"
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
}

function samePublicKey(left: KeyObject, right: KeyObject): boolean {
  const leftBytes = left.export({ type: "spki", format: "der" });
  const rightBytes = right.export({ type: "spki", format: "der" });
  return leftBytes.byteLength === rightBytes.byteLength && timingSafeEqual(leftBytes, rightBytes);
}

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new TypeError();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
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

function requiredDigest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError();
  return value;
}

function sameDigest(left: string, right: string): boolean {
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function noFollowFlag(): number {
  return fsConstants.O_NOFOLLOW ?? 0;
}

function directoryFlag(): number {
  return fsConstants.O_DIRECTORY ?? 0;
}
