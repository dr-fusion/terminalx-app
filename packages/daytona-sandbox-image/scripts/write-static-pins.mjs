#!/usr/local/bin/node

import { createHash, createPublicKey } from "node:crypto";
import {
  closeSync,
  constants,
  fchmodSync,
  fchownSync,
  fsyncSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  writeSync,
} from "node:fs";

const TRUST_INPUT = "/terminalx-build/inputs/sandbox-trust-input.json";
const PRODUCTION_SOURCE_INPUT = "/terminalx-build/inputs/daytona-production-source.json";
const RUNTIME_ARTIFACT_MANIFEST = "/usr/share/terminalx/daytona-runtime-artifact-manifest.json";
const NATIVE_HASHES = "/terminalx-build/native-hashes.json";
const BOOTSTRAP_AUTHORITY_PIN = "/etc/terminalx/bootstrap-authority-pin.json";
const OUTPUT = "/etc/terminalx/sandbox-trust-pins.json";
const TRUST_FIELDS = [
  "version",
  "kind",
  "supervisorArtifactDigest",
  "runtimeArtifactManifestDigest",
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
const NATIVE_FIELDS = [
  "isolationProbeSha256",
  "peerCredentialExecutableSha256",
  "sandboxInitSha256",
];
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const GITHUB_REPOSITORY =
  /^https:\/\/github\.com\/[a-z0-9](?:[a-z0-9-]{0,38})\/[A-Za-z0-9_.-]{1,100}$/;
const PRODUCTION_SOURCE_FIELDS = [
  "schemaVersion",
  "kind",
  "forkRepository",
  "productionForkCommit",
  "upstreamRepository",
  "upstreamBaseCommit",
];
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function createStaticTrustPins(
  trustInput,
  nativeHashes,
  productionSourceInput,
  runtimeArtifactManifestInput
) {
  const trust = exactRecord(trustInput, TRUST_FIELDS);
  const native = exactRecord(nativeHashes, NATIVE_FIELDS);
  const productionSource = productionSourcePin(productionSourceInput);
  const runtimeArtifacts = runtimeArtifactManifestPin(
    runtimeArtifactManifestInput,
    productionSource.productionForkCommit
  );
  const runtimeArtifactManifestDigest = digest(trust.runtimeArtifactManifestDigest);
  if (
    trust.version !== 1 ||
    trust.kind !== "terminalx.daytona-sandbox-trust-input" ||
    !GIT_COMMIT.test(trust.hardenedDaytonaSourceCommit) ||
    trust.hardenedDaytonaSourceCommit !== productionSource.productionForkCommit ||
    !KEY_ID.test(trust.isolationIssuerKeyId) ||
    !KEY_ID.test(trust.effectManifestAuthorityIssuerKeyId) ||
    !KEY_ID.test(trust.deploymentBindingIssuerKeyId)
  ) {
    throw new TypeError();
  }
  if (
    new Set([
      runtimeArtifactManifestDigest,
      runtimeArtifacts.runnerBinaryDigest,
      runtimeArtifacts.daemonBinaryDigest,
    ]).size !== 3
  ) {
    throw new TypeError();
  }
  const isolationPublicKey = canonicalEd25519PublicKey(trust.isolationIssuerPublicKeySpkiPem);
  const deploymentPublicKey = canonicalEd25519PublicKey(
    trust.deploymentBindingIssuerPublicKeySpkiPem
  );
  const effectManifestPublicKey = canonicalEd25519PublicKey(
    trust.effectManifestAuthorityPublicKeySpkiPem
  );
  if (
    new Set([
      trust.isolationIssuerKeyId,
      trust.effectManifestAuthorityIssuerKeyId,
      trust.deploymentBindingIssuerKeyId,
    ]).size !== 3 ||
    new Set([
      publicKeyDigest(isolationPublicKey),
      publicKeyDigest(effectManifestPublicKey),
      publicKeyDigest(deploymentPublicKey),
    ]).size !== 3
  ) {
    throw new TypeError();
  }
  const pins = Object.freeze({
    version: 2,
    kind: "terminalx.daytona-sandbox-trust-pins",
    supervisorArtifactDigest: digest(trust.supervisorArtifactDigest),
    runtimeArtifactManifestDigest,
    runnerBinaryDigest: runtimeArtifacts.runnerBinaryDigest,
    daemonBinaryDigest: runtimeArtifacts.daemonBinaryDigest,
    peerCredentialExecutableSha256: digest(native.peerCredentialExecutableSha256),
    effectExecutableSha256: digest(trust.effectExecutableSha256),
    nodeExecutableSha256: digest(trust.nodeExecutableSha256),
    isolationIssuerKeyId: trust.isolationIssuerKeyId,
    isolationIssuerPublicKeySpkiPem: isolationPublicKey,
    hardenedDaytonaSourceCommit: trust.hardenedDaytonaSourceCommit,
    effectManifestAuthorityIssuerKeyId: trust.effectManifestAuthorityIssuerKeyId,
    effectManifestAuthorityPublicKeySpkiPem: effectManifestPublicKey,
    deploymentBindingIssuerKeyId: trust.deploymentBindingIssuerKeyId,
    deploymentBindingIssuerPublicKeySpkiPem: deploymentPublicKey,
  });
  if (JSON.stringify(pins).includes("PRIVATE KEY")) throw new TypeError();
  return pins;
}

function run() {
  if (
    typeof process.geteuid !== "function" ||
    process.geteuid() !== 0 ||
    process.argv.length !== 2
  ) {
    throw new TypeError();
  }
  const trust = readProtectedJson(TRUST_INPUT, 256 * 1024, 0o600);
  const productionSource = readProtectedJson(PRODUCTION_SOURCE_INPUT, 16 * 1024, 0o600);
  const runtimeArtifacts = readProtectedJson(
    RUNTIME_ARTIFACT_MANIFEST,
    64 * 1024,
    0o444,
    digest(trust.runtimeArtifactManifestDigest),
    true
  );
  const native = readProtectedJson(NATIVE_HASHES, 16 * 1024, 0o600);
  const bootstrap = exactRecord(readProtectedJson(BOOTSTRAP_AUTHORITY_PIN, 64 * 1024, 0o600), [
    "version",
    "kind",
    "issuerKeyId",
    "publicKeySpkiPem",
  ]);
  const pins = createStaticTrustPins(trust, native, productionSource, runtimeArtifacts);
  const bootstrapPublicKey = canonicalEd25519PublicKey(bootstrap.publicKeySpkiPem);
  if (
    bootstrap.version !== 1 ||
    bootstrap.kind !== "terminalx.daytona-bootstrap-authority-pin" ||
    !KEY_ID.test(bootstrap.issuerKeyId) ||
    [
      pins.isolationIssuerKeyId,
      pins.effectManifestAuthorityIssuerKeyId,
      pins.deploymentBindingIssuerKeyId,
    ].includes(bootstrap.issuerKeyId) ||
    [
      pins.isolationIssuerPublicKeySpkiPem,
      pins.effectManifestAuthorityPublicKeySpkiPem,
      pins.deploymentBindingIssuerPublicKeySpkiPem,
    ].some((value) => publicKeyDigest(value) === publicKeyDigest(bootstrapPublicKey))
  ) {
    throw new TypeError();
  }
  assertExecutableDigest(
    "/usr/local/bin/daytona",
    pins.daemonBinaryDigest,
    0o555,
    256 * 1024 * 1024
  );
  assertExecutableDigest(
    "/usr/local/bin/node",
    pins.nodeExecutableSha256,
    0o555,
    256 * 1024 * 1024
  );
  assertExecutableDigest(
    "/usr/local/libexec/terminalx/terminalx-peercred",
    pins.peerCredentialExecutableSha256,
    0o500,
    16 * 1024 * 1024
  );
  assertExecutableDigest(
    "/usr/local/libexec/terminalx/terminalx-effect-enforcer",
    pins.effectExecutableSha256,
    0o500,
    128 * 1024 * 1024
  );
  writePrivateJson(OUTPUT, pins);
}

function readProtectedJson(path, maximumBytes, mode, expectedDigest, requireCanonical = false) {
  const status = lstatSync(path);
  let descriptor = -1;
  let bytes;
  if (
    !status.isFile() ||
    status.isSymbolicLink() ||
    status.nlink !== 1 ||
    status.uid !== 0 ||
    status.gid !== 0 ||
    (status.mode & 0o7777) !== mode ||
    status.size < 2 ||
    status.size > maximumBytes ||
    realpathSync.native(path) !== path
  ) {
    throw new TypeError();
  }
  try {
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
    if (
      expectedDigest !== undefined &&
      createHash("sha256").update(bytes).digest("hex") !== expectedDigest
    ) {
      throw new TypeError();
    }
    const parsed = JSON.parse(bytes.toString("utf8"));
    if (requireCanonical && bytes.toString("utf8") !== `${canonicalJson(parsed)}\n`) {
      throw new TypeError();
    }
    return parsed;
  } finally {
    bytes?.fill(0);
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function assertExecutableDigest(path, expected, mode, maximumBytes) {
  const status = lstatSync(path);
  let descriptor = -1;
  if (
    !status.isFile() ||
    status.isSymbolicLink() ||
    status.nlink !== 1 ||
    status.uid !== 0 ||
    status.gid !== 0 ||
    (status.mode & 0o7777) !== mode ||
    status.size < 1 ||
    status.size > maximumBytes ||
    realpathSync.native(path) !== path
  ) {
    throw new TypeError();
  }
  try {
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
    const hash = createHash("sha256");
    const chunk = Buffer.alloc(64 * 1024);
    let offset = 0;
    try {
      while (offset < opened.size) {
        const count = readSync(
          descriptor,
          chunk,
          0,
          Math.min(chunk.byteLength, opened.size - offset),
          offset
        );
        if (count < 1) throw new TypeError();
        hash.update(chunk.subarray(0, count));
        offset += count;
      }
    } finally {
      chunk.fill(0);
    }
    if (hash.digest("hex") !== expected) throw new TypeError();
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function writePrivateJson(path, value) {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  let descriptor = -1;
  try {
    descriptor = openSync(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600
    );
    fchownSync(descriptor, 0, 0);
    fchmodSync(descriptor, 0o600);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const count = writeSync(descriptor, bytes, offset, bytes.byteLength - offset);
      if (count < 1) throw new TypeError();
      offset += count;
    }
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = -1;
    const parent = openSync("/etc/terminalx", constants.O_RDONLY | constants.O_DIRECTORY);
    try {
      fsyncSync(parent);
    } finally {
      closeSync(parent);
    }
  } finally {
    bytes.fill(0);
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
    Object.keys(value).some((field) => !fields.includes(field))
  ) {
    throw new TypeError();
  }
  return value;
}

function productionSourcePin(value) {
  const source = exactRecord(value, PRODUCTION_SOURCE_FIELDS);
  if (
    source.schemaVersion !== 1 ||
    source.kind !== "terminalx.daytona-production-source" ||
    typeof source.forkRepository !== "string" ||
    !GITHUB_REPOSITORY.test(source.forkRepository) ||
    typeof source.upstreamRepository !== "string" ||
    !GITHUB_REPOSITORY.test(source.upstreamRepository) ||
    source.forkRepository === source.upstreamRepository ||
    typeof source.productionForkCommit !== "string" ||
    !GIT_COMMIT.test(source.productionForkCommit) ||
    typeof source.upstreamBaseCommit !== "string" ||
    !GIT_COMMIT.test(source.upstreamBaseCommit) ||
    source.productionForkCommit === source.upstreamBaseCommit
  ) {
    throw new TypeError();
  }
  return source;
}

function runtimeArtifactManifestPin(value, productionForkCommit) {
  const manifest = exactRecord(value, ["artifacts", "kind", "version"]);
  if (manifest.version !== 1 || manifest.kind !== "terminalx.daytona-hardened-runtime-artifacts") {
    throw new TypeError();
  }
  const artifacts = exactRecord(manifest.artifacts, ["daemon", "runner"]);
  const daemonBinaryDigest = runtimeArtifactPin(artifacts.daemon, productionForkCommit);
  const runnerBinaryDigest = runtimeArtifactPin(artifacts.runner, productionForkCommit);
  if (daemonBinaryDigest === runnerBinaryDigest) throw new TypeError();
  return Object.freeze({ daemonBinaryDigest, runnerBinaryDigest });
}

function runtimeArtifactPin(value, productionForkCommit) {
  const artifact = exactRecord(value, [
    "architecture",
    "binaryDigest",
    "operatingSystem",
    "sourceCommit",
  ]);
  if (
    artifact.architecture !== "amd64" ||
    artifact.operatingSystem !== "linux" ||
    artifact.sourceCommit !== productionForkCommit
  ) {
    throw new TypeError();
  }
  return digest(artifact.binaryDigest);
}

function canonicalEd25519PublicKey(value) {
  if (typeof value !== "string" || value.includes("PRIVATE KEY")) throw new TypeError();
  const key = createPublicKey(value);
  const canonical = key.export({ type: "spki", format: "pem" }).toString();
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519" || canonical !== value) {
    throw new TypeError();
  }
  return canonical;
}

function digest(value) {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError();
  return value;
}

function publicKeyDigest(value) {
  return createHash("sha256")
    .update(createPublicKey(value).export({ type: "spki", format: "der" }))
    .digest("hex");
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new TypeError();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    run();
  } catch {
    process.stderr.write("TerminalX static trust pin generation failed closed\n");
    process.exitCode = 1;
  }
}
