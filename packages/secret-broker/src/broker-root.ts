import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
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
import { dirname, isAbsolute, join, normalize } from "node:path";
import { AT_REST_KEY_BYTES } from "./at-rest";
import { domainSeparatedDigest, SecretBrokerProtocolError } from "./protocol";

const SIGNING_KEY_FILE = "signing-key.pk8";
const VERIFICATION_KEY_FILE = "verification-key.pem";
const AT_REST_KEY_FILE = "at-rest.key";
const INSTANCE_FILE = "instance.json";
export const BROKER_DATABASE_FILE = "broker.sqlite";
export const BROKER_SOCKET_FILE = "broker.sock";
export const BROKER_VERIFICATION_KEY_FILE = VERIFICATION_KEY_FILE;
const SIGNING_KEY_ID_DOMAIN = "terminalx/secret-broker-signing-key/v1\0";
const MAX_KEY_FILE_BYTES = 64 * 1024;

export interface BrokerRootContext {
  readonly rootDir: string;
  readonly signingKey: KeyObject;
  readonly verificationKey: KeyObject;
  readonly verificationKeyPem: string;
  readonly signingKeyId: string;
  readonly atRestKey: Buffer;
  readonly brokerInstanceId: string;
  readonly brokerEpoch: number;
  readonly databasePath: string;
  readonly socketPath: string;
}

export interface EstablishBrokerRootOptions {
  readonly rootDir: string;
  readonly expectedOwnerUid?: number;
}

/**
 * Validate the 0700 broker root, load or generate the Ed25519 signing key and
 * AES at-rest key on first boot, and advance the boot epoch. The signing and
 * at-rest keys never leave this process; only the public verification key is
 * published for the main-process receipt verifier.
 */
export function establishBrokerRoot(options: EstablishBrokerRootOptions): BrokerRootContext {
  const rootDir = canonicalAbsolutePath(options.rootDir);
  const expectedOwnerUid = resolveExpectedOwnerUid(options.expectedOwnerUid);
  assertPrivateDirectory(rootDir, expectedOwnerUid);

  const signingKey = loadOrCreateSigningKey(rootDir, expectedOwnerUid);
  const verificationKey = createPublicKey(signingKey);
  const verificationKeyPem = publishVerificationKey(rootDir, expectedOwnerUid, verificationKey);
  const atRestKey = loadOrCreateAtRestKey(rootDir, expectedOwnerUid);
  const instance = advanceInstanceEpoch(rootDir, expectedOwnerUid);

  return Object.freeze({
    rootDir,
    signingKey,
    verificationKey,
    verificationKeyPem,
    signingKeyId: domainSeparatedDigest(SIGNING_KEY_ID_DOMAIN, verificationKeyPem),
    atRestKey,
    brokerInstanceId: instance.brokerInstanceId,
    brokerEpoch: instance.brokerEpoch,
    databasePath: join(rootDir, BROKER_DATABASE_FILE),
    socketPath: join(rootDir, BROKER_SOCKET_FILE),
  });
}

function loadOrCreateSigningKey(rootDir: string, expectedOwnerUid: number): KeyObject {
  const path = join(rootDir, SIGNING_KEY_FILE);
  if (existsSync(path)) {
    const bytes = readPrivateFile(path, expectedOwnerUid);
    try {
      const key = createPrivateKeyChecked(bytes);
      return key;
    } finally {
      bytes.fill(0);
    }
  }
  const { privateKey } = generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  const bytes = Buffer.isBuffer(der) ? der : Buffer.from(der);
  try {
    writeExclusivePrivateFile(rootDir, path, bytes, expectedOwnerUid);
  } finally {
    bytes.fill(0);
  }
  return privateKey;
}

function createPrivateKeyChecked(bytes: Buffer): KeyObject {
  const key = createPrivateKey({ key: bytes, format: "der", type: "pkcs8" });
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") throw new TypeError();
  return key;
}

function publishVerificationKey(
  rootDir: string,
  expectedOwnerUid: number,
  verificationKey: KeyObject
): string {
  const pem = verificationKey.export({ type: "spki", format: "pem" });
  if (typeof pem !== "string") throw new SecretBrokerProtocolError("internal");
  const path = join(rootDir, VERIFICATION_KEY_FILE);
  if (existsSync(path)) {
    const existing = readPrivateFile(path, expectedOwnerUid).toString("utf8");
    if (existing !== pem) throw new SecretBrokerProtocolError("not-ready");
    return pem;
  }
  const bytes = Buffer.from(pem, "utf8");
  writeExclusivePrivateFile(rootDir, path, bytes, expectedOwnerUid);
  return pem;
}

function loadOrCreateAtRestKey(rootDir: string, expectedOwnerUid: number): Buffer {
  const path = join(rootDir, AT_REST_KEY_FILE);
  if (existsSync(path)) {
    const bytes = readPrivateFile(path, expectedOwnerUid);
    if (bytes.byteLength !== AT_REST_KEY_BYTES) {
      bytes.fill(0);
      throw new SecretBrokerProtocolError("not-ready");
    }
    return bytes;
  }
  const key = randomBytes(AT_REST_KEY_BYTES);
  writeExclusivePrivateFile(rootDir, path, key, expectedOwnerUid);
  return key;
}

interface InstanceRecord {
  readonly brokerInstanceId: string;
  readonly brokerEpoch: number;
}

function advanceInstanceEpoch(rootDir: string, expectedOwnerUid: number): InstanceRecord {
  const path = join(rootDir, INSTANCE_FILE);
  let brokerInstanceId = randomBytes(16).toString("hex");
  let bootCount = 0;
  if (existsSync(path)) {
    const bytes = readPrivateFile(path, expectedOwnerUid);
    try {
      const parsed = JSON.parse(bytes.toString("utf8")) as unknown;
      if (typeof parsed !== "object" || parsed === null) throw new TypeError();
      const record = parsed as Record<string, unknown>;
      if (
        typeof record.brokerInstanceId !== "string" ||
        !/^[0-9a-f]{32}$/.test(record.brokerInstanceId) ||
        !Number.isSafeInteger(record.bootCount) ||
        (record.bootCount as number) < 1
      ) {
        throw new TypeError();
      }
      brokerInstanceId = record.brokerInstanceId;
      bootCount = record.bootCount as number;
    } catch {
      throw new SecretBrokerProtocolError("not-ready");
    } finally {
      bytes.fill(0);
    }
  }
  const brokerEpoch = bootCount + 1;
  atomicReplacePrivateFile(
    rootDir,
    path,
    Buffer.from(`${JSON.stringify({ brokerInstanceId, bootCount: brokerEpoch })}\n`, "utf8"),
    expectedOwnerUid
  );
  return Object.freeze({ brokerInstanceId, brokerEpoch });
}

function resolveExpectedOwnerUid(value: number | undefined): number {
  if (value === undefined) {
    if (typeof process.geteuid !== "function") throw new SecretBrokerProtocolError("not-ready");
    return process.geteuid();
  }
  if (!Number.isSafeInteger(value) || value < 0) throw new SecretBrokerProtocolError("not-ready");
  return value;
}

function assertPrivateDirectory(rootDir: string, expectedOwnerUid: number): void {
  if (typeof process.geteuid === "function" && process.geteuid() !== expectedOwnerUid) {
    throw new SecretBrokerProtocolError("permission-denied");
  }
  try {
    if (realpathSync.native(rootDir) !== rootDir) throw new TypeError();
    const stat = lstatSync(rootDir);
    if (
      stat.isSymbolicLink() ||
      !stat.isDirectory() ||
      stat.uid !== expectedOwnerUid ||
      (stat.mode & 0o077) !== 0
    ) {
      throw new TypeError();
    }
  } catch {
    throw new SecretBrokerProtocolError("not-ready");
  }
}

function readPrivateFile(path: string, expectedOwnerUid: number): Buffer {
  let descriptor = -1;
  try {
    const link = lstatSync(path);
    if (link.isSymbolicLink()) throw new TypeError();
    descriptor = openSync(path, fsConstants.O_RDONLY | noFollowFlag());
    const stat = fstatSync(descriptor);
    requirePrivateRegular(stat, expectedOwnerUid);
    return readFileSync(descriptor);
  } catch {
    throw new SecretBrokerProtocolError("not-ready");
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function writeExclusivePrivateFile(
  rootDir: string,
  path: string,
  bytes: Buffer,
  expectedOwnerUid: number
): void {
  let descriptor = -1;
  try {
    descriptor = openSync(
      path,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollowFlag(),
      0o600
    );
    const stat = fstatSync(descriptor);
    requirePrivateRegular(stat, expectedOwnerUid);
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } catch {
    if (descriptor >= 0) closeSync(descriptor);
    throw new SecretBrokerProtocolError("not-ready");
  }
  closeSync(descriptor);
  fsyncDirectory(rootDir);
}

function atomicReplacePrivateFile(
  rootDir: string,
  path: string,
  bytes: Buffer,
  expectedOwnerUid: number
): void {
  const temporary = join(rootDir, `.${randomBytes(12).toString("hex")}.tmp`);
  let descriptor = -1;
  try {
    descriptor = openSync(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollowFlag(),
      0o600
    );
    const stat = fstatSync(descriptor);
    requirePrivateRegular(stat, expectedOwnerUid);
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = -1;
    if (dirname(path) !== rootDir) throw new TypeError();
    renameSync(temporary, path);
    fsyncDirectory(rootDir);
  } catch {
    if (descriptor >= 0) closeSync(descriptor);
    try {
      unlinkSync(temporary);
    } catch {
      // The rename may already have consumed the temporary file.
    }
    throw new SecretBrokerProtocolError("not-ready");
  }
}

function requirePrivateRegular(stat: Stats, expectedOwnerUid: number): void {
  if (
    !stat.isFile() ||
    stat.nlink !== 1 ||
    stat.uid !== expectedOwnerUid ||
    (stat.mode & 0o077) !== 0 ||
    stat.size > MAX_KEY_FILE_BYTES
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
    throw new SecretBrokerProtocolError("not-ready");
  }
  return value;
}

function noFollowFlag(): number {
  return fsConstants.O_NOFOLLOW ?? 0;
}

function directoryFlag(): number {
  return fsConstants.O_DIRECTORY ?? 0;
}
