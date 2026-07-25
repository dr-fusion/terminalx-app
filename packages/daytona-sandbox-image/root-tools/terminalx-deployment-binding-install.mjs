#!/usr/local/bin/node

import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fchownSync,
  fdatasyncSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";

const MAX_INPUT_BYTES = 256 * 1024;
const MAX_EXISTING_BYTES = 256 * 1024;
const MAX_TTL_MS = 5 * 60_000;
const RUNTIME_ROOT = "/run/terminalx-root";
const TARGET_FILE = "/run/terminalx-root/deployment-binding.json";
const TRUST_PIN_FILE = "/etc/terminalx/sandbox-trust-pins.json";
const KIND = "terminalx.daytona-sandbox-deployment-binding";
const CLAIMS_DOMAIN = "terminalx/daytona-sandbox-deployment-binding-claims/v1\0";
const SIGNATURE_DOMAIN = "terminalx/daytona-sandbox-deployment-binding-authority/v1\0";
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/u;
const PIN_FIELDS = [
  "version",
  "kind",
  "supervisorArtifactDigest",
  "runtimeArtifactManifestDigest",
  "runnerBinaryDigest",
  "daemonBinaryDigest",
  "peerCredentialExecutableSha256",
  "effectExecutableSha256",
  "nodeExecutableSha256",
  "isolationIssuerKeyId",
  "isolationIssuerPublicKeySpkiPem",
  "hardenedDaytonaSourceCommit",
  "effectManifestAuthorityIssuerKeyId",
  "effectManifestAuthorityPublicKeySpkiPem",
  "deploymentBindingIssuerKeyId",
  "deploymentBindingIssuerPublicKeySpkiPem",
];

class InstallError extends Error {
  constructor(exitCode) {
    super("TerminalX deployment binding install failed closed");
    this.exitCode = exitCode;
  }
}

export async function runDeploymentBindingInstall() {
  if (
    typeof process.geteuid !== "function" ||
    process.geteuid() !== 0 ||
    process.argv.length !== 2
  ) {
    throw new InstallError(64);
  }
  validateFixedEnvironment(process.env);
  const input = await readBoundedStdin();
  try {
    const binding = parseCanonicalBinding(input);
    if (isByteIdenticalReplay(input)) {
      validateSignedBinding(binding, false);
      return;
    }
    const validated = validateSignedBinding(binding, true);
    installIdempotently(input, validated);
  } finally {
    input.fill(0);
  }
}

function isByteIdenticalReplay(bytes) {
  assertProtectedDirectory(RUNTIME_ROOT, 0o700);
  const existing = readExistingTarget();
  if (existing === null) return false;
  try {
    return existing.byteLength === bytes.byteLength && timingSafeEqual(existing, bytes);
  } finally {
    existing.fill(0);
  }
}

function validateFixedEnvironment(environment) {
  const keys = Object.keys(environment);
  if (
    keys.length !== 3 ||
    !keys.includes("DAYTONA_SANDBOX_ID") ||
    !keys.includes("DAYTONA_SANDBOX_SNAPSHOT") ||
    !keys.includes("DAYTONA_SANDBOX_USER") ||
    !UUID_V4.test(environment.DAYTONA_SANDBOX_ID ?? "") ||
    !SAFE_REFERENCE.test(environment.DAYTONA_SANDBOX_SNAPSHOT ?? "") ||
    environment.DAYTONA_SANDBOX_USER !== "terminalx"
  ) {
    throw new InstallError(64);
  }
}

async function readBoundedStdin() {
  const allocation = Buffer.alloc(MAX_INPUT_BYTES + 1);
  let length = 0;
  try {
    for await (const unsafeChunk of process.stdin) {
      const chunk = Buffer.isBuffer(unsafeChunk) ? unsafeChunk : Buffer.from(unsafeChunk);
      try {
        if (length + chunk.byteLength > MAX_INPUT_BYTES) throw new InstallError(64);
        chunk.copy(allocation, length);
        length += chunk.byteLength;
      } finally {
        chunk.fill(0);
      }
    }
    if (length < 2) throw new InstallError(64);
    return Buffer.from(allocation.subarray(0, length));
  } finally {
    allocation.fill(0);
  }
}

function parseCanonicalBinding(bytes) {
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new InstallError(64);
  }
  const binding = exactRecord(parsed, [
    "version",
    "kind",
    "providerSandboxId",
    "providerRevision",
    "sandboxArtifactDigest",
    "expectedSandboxImageId",
    "expectedSandboxSnapshotRef",
    "authority",
  ]);
  exactRecord(binding.authority, [
    "issuer",
    "issuerKeyId",
    "audience",
    "capability",
    "claimsDigest",
    "issuedAtMs",
    "expiresAtMs",
    "signature",
  ]);
  if (canonicalJson(binding) !== bytes.toString("utf8")) throw new InstallError(64);
  return binding;
}

function validateSignedBinding(binding, requireFresh) {
  const pins = readTrustedJson(TRUST_PIN_FILE, PIN_FIELDS, 256 * 1024);
  const authority = binding.authority;
  const claims = {
    version: integer(binding.version, 1, 1),
    kind: exactString(binding.kind, KIND),
    providerSandboxId: uuid(binding.providerSandboxId),
    providerRevision: integer(binding.providerRevision, 1, Number.MAX_SAFE_INTEGER),
    sandboxArtifactDigest: digest(binding.sandboxArtifactDigest),
    expectedSandboxImageId: imageId(binding.expectedSandboxImageId),
    expectedSandboxSnapshotRef: safeReference(binding.expectedSandboxSnapshotRef),
  };
  const claimsDigest = createHash("sha256")
    .update(CLAIMS_DOMAIN, "utf8")
    .update(canonicalJson(claims), "utf8")
    .digest("hex");
  const issuedAtMs = integer(authority.issuedAtMs, 0, Number.MAX_SAFE_INTEGER);
  const expiresAtMs = integer(authority.expiresAtMs, 1, Number.MAX_SAFE_INTEGER);
  const now = Date.now();
  if (
    pins.version !== 2 ||
    pins.kind !== "terminalx.daytona-sandbox-trust-pins" ||
    !SHA256.test(pins.runtimeArtifactManifestDigest) ||
    !SHA256.test(pins.runnerBinaryDigest) ||
    !SHA256.test(pins.daemonBinaryDigest) ||
    new Set([pins.runtimeArtifactManifestDigest, pins.runnerBinaryDigest, pins.daemonBinaryDigest])
      .size !== 3 ||
    authority.issuer !== "daytona-runner" ||
    authority.issuerKeyId !== pins.deploymentBindingIssuerKeyId ||
    authority.audience !== "terminalx-assignment-bootstrap" ||
    authority.capability !== "sandbox.deployment.bind" ||
    !sameDigest(authority.claimsDigest, claimsDigest) ||
    typeof authority.signature !== "string" ||
    !SIGNATURE.test(authority.signature) ||
    expiresAtMs <= issuedAtMs ||
    expiresAtMs - issuedAtMs > MAX_TTL_MS ||
    claims.providerSandboxId !== process.env.DAYTONA_SANDBOX_ID ||
    claims.expectedSandboxSnapshotRef !== process.env.DAYTONA_SANDBOX_SNAPSHOT
  ) {
    throw new InstallError(64);
  }
  if (requireFresh && (now < issuedAtMs || now >= expiresAtMs)) {
    throw new InstallError(64);
  }
  let publicKey;
  try {
    publicKey = createPublicKey(pins.deploymentBindingIssuerPublicKeySpkiPem);
    if (
      publicKey.type !== "public" ||
      publicKey.asymmetricKeyType !== "ed25519" ||
      publicKey.export({ type: "spki", format: "pem" }).toString() !==
        pins.deploymentBindingIssuerPublicKeySpkiPem
    ) {
      throw new TypeError();
    }
  } catch {
    throw new InstallError(74);
  }
  const statement = {
    version: 1,
    issuer: "daytona-runner",
    issuerKeyId: authority.issuerKeyId,
    audience: "terminalx-assignment-bootstrap",
    capability: "sandbox.deployment.bind",
    claimsDigest,
    issuedAtMs,
    expiresAtMs,
  };
  let valid = false;
  try {
    valid = verify(
      null,
      Buffer.from(`${SIGNATURE_DOMAIN}${canonicalJson(statement)}`, "utf8"),
      publicKey,
      Buffer.from(authority.signature, "base64url")
    );
  } catch {
    valid = false;
  }
  if (!valid) throw new InstallError(64);
  return Object.freeze({ claimsCanonical: canonicalJson(claims), issuedAtMs });
}

function installIdempotently(bytes, validated) {
  assertProtectedDirectory(RUNTIME_ROOT, 0o700);
  const existing = readExistingTarget();
  let replace = false;
  if (existing !== null) {
    if (existing.byteLength === bytes.byteLength && timingSafeEqual(existing, bytes)) {
      existing.fill(0);
      return;
    }
    let previous;
    try {
      previous = validateSignedBinding(parseCanonicalBinding(existing), false);
    } catch {
      existing.fill(0);
      throw new InstallError(74);
    }
    if (
      previous.claimsCanonical !== validated.claimsCanonical ||
      validated.issuedAtMs <= previous.issuedAtMs
    ) {
      existing.fill(0);
      throw new InstallError(73);
    }
    replace = true;
  }

  const temporary = `${RUNTIME_ROOT}/.deployment-binding-${randomBytes(16).toString("hex")}`;
  let descriptor = -1;
  try {
    descriptor = openSync(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600
    );
    fchmodSync(descriptor, 0o600);
    fchownSync(descriptor, 0, 0);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const count = writeSync(descriptor, bytes, offset, bytes.byteLength - offset);
      if (count < 1) throw new InstallError(74);
      offset += count;
    }
    fdatasyncSync(descriptor);
    closeSync(descriptor);
    descriptor = -1;
    if (replace) {
      const latest = readExistingTarget();
      if (latest === null) throw new InstallError(74);
      try {
        if (latest.byteLength !== existing.byteLength || !timingSafeEqual(latest, existing)) {
          throw new InstallError(73);
        }
      } finally {
        latest.fill(0);
      }
      renameSync(temporary, TARGET_FILE);
    } else {
      try {
        linkSync(temporary, TARGET_FILE);
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        const raced = readExistingTarget();
        if (raced === null) throw new InstallError(74);
        try {
          if (raced.byteLength !== bytes.byteLength || !timingSafeEqual(raced, bytes)) {
            throw new InstallError(73);
          }
        } finally {
          raced.fill(0);
        }
      }
      unlinkSync(temporary);
    }
    fsyncDirectory(RUNTIME_ROOT);
  } catch (error) {
    if (descriptor >= 0) closeSync(descriptor);
    try {
      unlinkSync(temporary);
    } catch {
      // Best-effort cleanup; a leftover root-only temporary file remains fail closed.
    }
    if (error instanceof InstallError) throw error;
    throw new InstallError(74);
  } finally {
    if (existing !== null) existing.fill(0);
  }
}

function readExistingTarget() {
  let status;
  try {
    status = lstatSync(TARGET_FILE);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw new InstallError(74);
  }
  if (
    !status.isFile() ||
    status.isSymbolicLink() ||
    status.nlink !== 1 ||
    status.uid !== 0 ||
    status.gid !== 0 ||
    (status.mode & 0o7777) !== 0o600 ||
    status.size < 2 ||
    status.size > MAX_EXISTING_BYTES ||
    realpathSync.native(TARGET_FILE) !== TARGET_FILE
  ) {
    throw new InstallError(74);
  }
  let descriptor = -1;
  try {
    descriptor = openSync(TARGET_FILE, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor);
    if (
      opened.dev !== status.dev ||
      opened.ino !== status.ino ||
      opened.size !== status.size ||
      opened.mtimeMs !== status.mtimeMs
    ) {
      throw new InstallError(74);
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const count = readSync(descriptor, bytes, offset, bytes.byteLength - offset, offset);
      if (count < 1) throw new InstallError(74);
      offset += count;
    }
    return bytes;
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function readTrustedJson(path, fields, maximumBytes) {
  let status;
  let descriptor = -1;
  let bytes;
  try {
    status = lstatSync(path);
    if (
      !status.isFile() ||
      status.isSymbolicLink() ||
      status.nlink !== 1 ||
      status.uid !== 0 ||
      status.gid !== 0 ||
      (status.mode & 0o7777) !== 0o600 ||
      status.size < 2 ||
      status.size > maximumBytes ||
      realpathSync.native(path) !== path
    ) {
      throw new TypeError();
    }
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor);
    if (
      opened.dev !== status.dev ||
      opened.ino !== status.ino ||
      opened.size !== status.size ||
      opened.mtimeMs !== status.mtimeMs
    ) {
      throw new TypeError();
    }
    bytes = readFileSync(descriptor);
    return exactRecord(JSON.parse(bytes.toString("utf8")), fields);
  } catch {
    throw new InstallError(74);
  } finally {
    bytes?.fill(0);
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function assertProtectedDirectory(path, mode) {
  try {
    const status = lstatSync(path);
    if (
      !status.isDirectory() ||
      status.isSymbolicLink() ||
      status.uid !== 0 ||
      status.gid !== 0 ||
      (status.mode & 0o7777) !== mode ||
      realpathSync.native(path) !== path
    ) {
      throw new TypeError();
    }
  } catch {
    throw new InstallError(74);
  }
}

function fsyncDirectory(path) {
  let descriptor = -1;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY);
    fsyncSync(descriptor);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function exactRecord(value, fields) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== fields.length ||
    Object.keys(value).some((key) => !fields.includes(key))
  ) {
    throw new InstallError(64);
  }
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new InstallError(64);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value !== "object") throw new InstallError(64);
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function integer(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new InstallError(64);
  }
  return value;
}

function exactString(value, expected) {
  if (value !== expected) throw new InstallError(64);
  return value;
}

function uuid(value) {
  if (typeof value !== "string" || !UUID_V4.test(value)) throw new InstallError(64);
  return value;
}

function digest(value) {
  if (typeof value !== "string" || !SHA256.test(value)) throw new InstallError(64);
  return value;
}

function imageId(value) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new InstallError(64);
  }
  return value;
}

function safeReference(value) {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) throw new InstallError(64);
  return value;
}

function sameDigest(left, right) {
  if (typeof left !== "string" || !SHA256.test(left)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  runDeploymentBindingInstall().catch((error) => {
    process.stderr.write("TerminalX deployment binding install failed closed\n");
    process.exitCode = error instanceof InstallError ? error.exitCode : 74;
  });
}
