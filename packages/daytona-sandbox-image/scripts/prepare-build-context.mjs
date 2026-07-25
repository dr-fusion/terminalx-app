#!/usr/bin/env node

import { createHash, createPublicKey } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { loadDaytonaProductionSource } from "../../../scripts/lib/daytona-production-source.mjs";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const productionSource = loadDaytonaProductionSource();
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const CONTENT_IMAGE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,300}@sha256:[0-9a-f]{64}$/;
const IMAGE_NAME = /^[a-z0-9][a-z0-9._:/-]{0,250}$/;
const PRIVATE_PEM =
  /-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{16,}?-----END (?:ENCRYPTED |RSA |EC |OPENSSH )?PRIVATE KEY-----/;
const CONFIG_FIELDS = [
  "schemaVersion",
  "dockerfileFrontendImage",
  "runtimeImage",
  "toolchainImage",
  "platform",
  "imageName",
  "sourceDateEpoch",
  "supervisorArchiveFile",
  "supervisorArtifactDigest",
  "daytonaRuntimeArtifactManifestFile",
  "daytonaRuntimeArtifactManifestDigest",
  "daytonaDaemonFile",
  "effectEnforcerFile",
  "effectEnforcerSha256",
  "nodeExecutableSha256",
  "bootstrapAuthorityPinFile",
  "trust",
];
const TRUST_FIELDS = [
  "isolationIssuerKeyId",
  "isolationIssuerPublicKeySpkiPem",
  "hardenedDaytonaSourceCommit",
  "effectManifestAuthorityIssuerKeyId",
  "effectManifestAuthorityPublicKeySpkiPem",
  "deploymentBindingIssuerKeyId",
  "deploymentBindingIssuerPublicKeySpkiPem",
];
const AUTHORITY_PIN_FIELDS = ["version", "kind", "issuerKeyId", "publicKeySpkiPem"];

export function prepareBuildContext(configurationFile, outputDirectory) {
  const configurationPath = canonicalSourcePath(configurationFile, "configuration");
  const outputRoot = resolve(outputDirectory);
  requireEmptyOutput(outputRoot);
  const configuration = exactRecord(
    JSON.parse(readProtectedFile(configurationPath, 512 * 1024, false).toString("utf8")),
    CONFIG_FIELDS,
    "configuration"
  );
  assertNoPrivateMaterial(configuration, "configuration");
  const snapshot = snapshotConfiguration(configuration);

  mkdirSync(outputRoot, { mode: 0o700 });
  mkdirSync(join(outputRoot, "inputs"), { mode: 0o700 });
  mkdirSync(join(outputRoot, "root-tools"), { mode: 0o700 });
  mkdirSync(join(outputRoot, "scripts"), { mode: 0o700 });

  const archive = readProtectedFile(
    snapshot.supervisorArchiveFile,
    256 * 1024 * 1024,
    false,
    snapshot.supervisorArtifactDigest
  );
  const supervisorMembers = readSupervisorArchive(archive);
  const artifact = validateSupervisorArtifact(
    supervisorMembers.manifest,
    supervisorMembers.executables,
    snapshot.trust.hardenedDaytonaSourceCommit
  );
  const runtimeArtifactManifestBytes = readProtectedFile(
    snapshot.daytonaRuntimeArtifactManifestFile,
    64 * 1024,
    false,
    snapshot.daytonaRuntimeArtifactManifestDigest
  );
  const runtimeArtifactManifest = validateRuntimeArtifactManifest(
    runtimeArtifactManifestBytes,
    snapshot.trust.hardenedDaytonaSourceCommit
  );
  if (
    new Set([
      snapshot.daytonaRuntimeArtifactManifestDigest,
      runtimeArtifactManifest.artifacts.daemon.binaryDigest,
      runtimeArtifactManifest.artifacts.runner.binaryDigest,
    ]).size !== 3
  ) {
    throw new TypeError("Runtime manifest, daemon, and runner digests must be distinct");
  }
  const daytona = readProtectedFile(
    snapshot.daytonaDaemonFile,
    256 * 1024 * 1024,
    true,
    runtimeArtifactManifest.artifacts.daemon.binaryDigest
  );
  const effect = readProtectedFile(
    snapshot.effectEnforcerFile,
    128 * 1024 * 1024,
    true,
    snapshot.effectEnforcerSha256
  );
  assertExecutableFormat(daytona, "Daytona daemon", false);
  assertExecutableFormat(effect, "effect enforcer", true);
  assertNoEmbeddedPrivatePem(daytona, "Daytona daemon");
  assertNoEmbeddedPrivatePem(effect, "effect enforcer");
  archive.fill(0);

  const bootstrapPin = validateBootstrapAuthorityPin(snapshot.bootstrapAuthorityPinFile);
  const publicKeys = [
    bootstrapPin.publicKeySpkiPem,
    snapshot.trust.isolationIssuerPublicKeySpkiPem,
    snapshot.trust.effectManifestAuthorityPublicKeySpkiPem,
    snapshot.trust.deploymentBindingIssuerPublicKeySpkiPem,
  ];
  if (new Set(publicKeys.map(publicKeyDigest)).size !== publicKeys.length) {
    throw new TypeError("Production trust roles must use distinct Ed25519 public keys");
  }
  if (
    new Set([
      bootstrapPin.issuerKeyId,
      snapshot.trust.isolationIssuerKeyId,
      snapshot.trust.effectManifestAuthorityIssuerKeyId,
      snapshot.trust.deploymentBindingIssuerKeyId,
    ]).size !== 4
  ) {
    throw new TypeError("Production trust roles must use distinct key identifiers");
  }

  const dockerfileTemplate = readPackageFile("Dockerfile", 512 * 1024);
  const dockerfileMarker = "# syntax=TERMINALX_REQUIRES_PREPARED_CONTENT_ADDRESSED_FRONTEND";
  const dockerfileText = dockerfileTemplate.toString("utf8");
  if (
    !dockerfileText.startsWith(`${dockerfileMarker}\n`) ||
    dockerfileText.indexOf(dockerfileMarker, dockerfileMarker.length) !== -1
  ) {
    dockerfileTemplate.fill(0);
    throw new TypeError("Dockerfile frontend pin seam is invalid");
  }
  const dockerfile = Buffer.from(
    dockerfileText.replace(dockerfileMarker, `# syntax=${snapshot.dockerfileFrontendImage}`),
    "utf8"
  );
  dockerfileTemplate.fill(0);
  writeExclusive(join(outputRoot, "Dockerfile"), dockerfile, 0o600);
  dockerfile.fill(0);
  writeExclusive(
    join(outputRoot, "root-tools", "terminalx-sandbox-init.c"),
    readPackageFile("root-tools/terminalx-sandbox-init.c", 512 * 1024),
    0o600
  );
  writeExclusive(
    join(outputRoot, "root-tools", "terminalx-peercred.c"),
    readPackageFile("root-tools/terminalx-peercred.c", 128 * 1024),
    0o600
  );
  writeExclusive(
    join(outputRoot, "root-tools", "terminalx-isolation-probe.c"),
    readPackageFile("root-tools/terminalx-isolation-probe.c", 512 * 1024),
    0o600
  );
  const bindingInstaller = readPackageFile(
    "root-tools/terminalx-deployment-binding-install.mjs",
    512 * 1024
  );
  writeExclusive(
    join(outputRoot, "inputs", "terminalx-deployment-binding-install"),
    bindingInstaller,
    0o555
  );
  writeExclusive(
    join(outputRoot, "scripts", "write-static-pins.mjs"),
    readPackageFile("scripts/write-static-pins.mjs", 512 * 1024),
    0o500
  );
  writeExclusive(
    join(outputRoot, "scripts", "audit-final-rootfs.mjs"),
    readPackageFile("scripts/audit-final-rootfs.mjs", 256 * 1024),
    0o500
  );
  writeExclusive(join(outputRoot, "inputs", "daytona"), daytona, 0o555);
  daytona.fill(0);
  writeExclusive(join(outputRoot, "inputs", "terminalx-effect-enforcer"), effect, 0o500);
  effect.fill(0);
  for (const [role, executable] of Object.entries(supervisorMembers.executables)) {
    writeExclusive(join(outputRoot, "inputs", role), executable.bytes, 0o555);
    executable.bytes.fill(0);
  }
  writeExclusive(
    join(outputRoot, "inputs", "daytona-supervisor-artifact.json"),
    Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`, "utf8"),
    0o444
  );
  writeExclusive(
    join(outputRoot, "inputs", "daytona-runtime-artifact-manifest.json"),
    runtimeArtifactManifestBytes,
    0o444
  );
  runtimeArtifactManifestBytes.fill(0);
  writeExclusive(
    join(outputRoot, "inputs", "bootstrap-authority-pin.json"),
    Buffer.from(`${canonicalJson(bootstrapPin)}\n`, "utf8"),
    0o600
  );
  const trustInput = Object.freeze({
    version: 1,
    kind: "terminalx.daytona-sandbox-trust-input",
    supervisorArtifactDigest: snapshot.supervisorArtifactDigest,
    runtimeArtifactManifestDigest: snapshot.daytonaRuntimeArtifactManifestDigest,
    effectExecutableSha256: snapshot.effectEnforcerSha256,
    nodeExecutableSha256: snapshot.nodeExecutableSha256,
    ...snapshot.trust,
  });
  writeExclusive(
    join(outputRoot, "inputs", "sandbox-trust-input.json"),
    Buffer.from(`${canonicalJson(trustInput)}\n`, "utf8"),
    0o600
  );
  writeExclusive(
    join(outputRoot, "inputs", "daytona-production-source.json"),
    Buffer.from(`${canonicalJson(productionSource)}\n`, "utf8"),
    0o600
  );

  const relay = supervisorMembers.executables["terminalx-supervisor-relay"];
  const bootstrap = supervisorMembers.executables["terminalx-assignment-bootstrap"];
  const supervisor = supervisorMembers.executables["terminalx-daytona-supervisor"];
  const installerSha = sha256(bindingInstaller);
  const buildArguments = [
    ["BUILDKIT_SYNTAX", snapshot.dockerfileFrontendImage],
    ["TERMINALX_RUNTIME_IMAGE", snapshot.runtimeImage],
    ["TERMINALX_TOOLCHAIN_IMAGE", snapshot.toolchainImage],
    ["SOURCE_DATE_EPOCH", String(snapshot.sourceDateEpoch)],
    ["TERMINALX_SUPERVISOR_ARTIFACT_SHA256", snapshot.supervisorArtifactDigest],
    ["TERMINALX_SUPERVISOR_SHA256", supervisor.sha256],
    ["TERMINALX_SUPERVISOR_RELAY_SHA256", relay.sha256],
    ["TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256", bootstrap.sha256],
    ["TERMINALX_RUNTIME_ARTIFACT_MANIFEST_SHA256", snapshot.daytonaRuntimeArtifactManifestDigest],
    ["TERMINALX_RUNNER_BINARY_SHA256", runtimeArtifactManifest.artifacts.runner.binaryDigest],
    ["TERMINALX_DAYTONA_DAEMON_SHA256", runtimeArtifactManifest.artifacts.daemon.binaryDigest],
    ["TERMINALX_EFFECT_ENFORCER_SHA256", snapshot.effectEnforcerSha256],
    ["TERMINALX_NODE_SHA256", snapshot.nodeExecutableSha256],
    ["TERMINALX_DEPLOYMENT_BINDING_INSTALL_SHA256", installerSha],
    ["TERMINALX_SOURCE_COMMIT", artifact.source.terminalxCommit],
    ["TERMINALX_DAYTONA_SOURCE_COMMIT", snapshot.trust.hardenedDaytonaSourceCommit],
  ];
  writeExclusive(
    join(outputRoot, "build-arguments.txt"),
    Buffer.from(buildArguments.map(([key, value]) => `${key}=${value}`).join("\n") + "\n"),
    0o600
  );
  writeExclusive(join(outputRoot, "image-name.txt"), Buffer.from(`${snapshot.imageName}\n`), 0o600);
  writeExclusive(join(outputRoot, "platform.txt"), Buffer.from(`${snapshot.platform}\n`), 0o600);
  writeExclusive(
    join(outputRoot, ".dockerignore"),
    Buffer.from("*\n!Dockerfile\n!inputs/**\n!native-hashes.json\n!root-tools/**\n!scripts/**\n"),
    0o600
  );
  chmodSync(outputRoot, 0o700);
  return Object.freeze({
    artifact,
    runtimeArtifactManifest,
    buildArguments: Object.freeze(Object.fromEntries(buildArguments)),
    imageName: snapshot.imageName,
    platform: snapshot.platform,
  });
}

function snapshotConfiguration(value) {
  const trust = exactRecord(value.trust, TRUST_FIELDS, "trust");
  const dockerfileFrontendImage = contentImage(
    value.dockerfileFrontendImage,
    "dockerfileFrontendImage"
  );
  const runtimeImage = contentImage(value.runtimeImage, "runtimeImage");
  const toolchainImage = contentImage(value.toolchainImage, "toolchainImage");
  if (new Set([dockerfileFrontendImage, runtimeImage, toolchainImage]).size !== 3) {
    throw new TypeError(
      "Build frontend, runtime, and toolchain images must be independently pinned"
    );
  }
  if (value.schemaVersion !== 1) {
    throw new TypeError("Unsupported sandbox image build configuration version");
  }
  if (value.platform !== "linux/amd64") {
    throw new TypeError("Only the manifest-bound linux/amd64 platform is supported");
  }
  if (
    typeof value.imageName !== "string" ||
    !IMAGE_NAME.test(value.imageName) ||
    value.imageName.includes("@") ||
    value.imageName.slice(value.imageName.lastIndexOf("/") + 1).includes(":")
  ) {
    throw new TypeError("Invalid output image name");
  }
  if (!Number.isSafeInteger(value.sourceDateEpoch) || value.sourceDateEpoch < 0) {
    throw new TypeError("Invalid SOURCE_DATE_EPOCH");
  }
  const hardenedCommit = gitCommit(
    trust.hardenedDaytonaSourceCommit,
    "hardenedDaytonaSourceCommit"
  );
  if (hardenedCommit !== productionSource.productionForkCommit) {
    throw new TypeError("The Daytona source commit is not the pinned production fork commit");
  }
  return Object.freeze({
    dockerfileFrontendImage,
    runtimeImage,
    toolchainImage,
    platform: value.platform,
    imageName: value.imageName,
    sourceDateEpoch: value.sourceDateEpoch,
    supervisorArchiveFile: canonicalSourcePath(value.supervisorArchiveFile, "supervisor archive"),
    supervisorArtifactDigest: digest(value.supervisorArtifactDigest, "supervisorArtifactDigest"),
    daytonaRuntimeArtifactManifestFile: canonicalSourcePath(
      value.daytonaRuntimeArtifactManifestFile,
      "Daytona runtime artifact manifest"
    ),
    daytonaRuntimeArtifactManifestDigest: digest(
      value.daytonaRuntimeArtifactManifestDigest,
      "daytonaRuntimeArtifactManifestDigest"
    ),
    daytonaDaemonFile: canonicalSourcePath(value.daytonaDaemonFile, "Daytona daemon"),
    effectEnforcerFile: canonicalSourcePath(value.effectEnforcerFile, "effect enforcer"),
    effectEnforcerSha256: digest(value.effectEnforcerSha256, "effectEnforcerSha256"),
    nodeExecutableSha256: digest(value.nodeExecutableSha256, "nodeExecutableSha256"),
    bootstrapAuthorityPinFile: canonicalSourcePath(
      value.bootstrapAuthorityPinFile,
      "bootstrap authority pin"
    ),
    trust: Object.freeze({
      isolationIssuerKeyId: keyId(trust.isolationIssuerKeyId, "isolationIssuerKeyId"),
      isolationIssuerPublicKeySpkiPem: canonicalEd25519PublicKey(
        trust.isolationIssuerPublicKeySpkiPem,
        "isolation issuer"
      ),
      hardenedDaytonaSourceCommit: hardenedCommit,
      effectManifestAuthorityIssuerKeyId: keyId(
        trust.effectManifestAuthorityIssuerKeyId,
        "effectManifestAuthorityIssuerKeyId"
      ),
      effectManifestAuthorityPublicKeySpkiPem: canonicalEd25519PublicKey(
        trust.effectManifestAuthorityPublicKeySpkiPem,
        "effect manifest authority"
      ),
      deploymentBindingIssuerKeyId: keyId(
        trust.deploymentBindingIssuerKeyId,
        "deploymentBindingIssuerKeyId"
      ),
      deploymentBindingIssuerPublicKeySpkiPem: canonicalEd25519PublicKey(
        trust.deploymentBindingIssuerPublicKeySpkiPem,
        "deployment binding issuer"
      ),
    }),
  });
}

function validateRuntimeArtifactManifest(bytes, hardenedDaytonaCommit) {
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new TypeError("Daytona runtime artifact manifest is invalid JSON");
  }
  const canonicalBytes = Buffer.from(`${canonicalJson(manifest)}\n`, "utf8");
  try {
    if (!bytes.equals(canonicalBytes)) {
      throw new TypeError(
        "Daytona runtime artifact manifest must be canonical one-line JSON followed by LF"
      );
    }
  } finally {
    canonicalBytes.fill(0);
  }
  const record = exactRecord(
    manifest,
    ["artifacts", "kind", "version"],
    "Daytona runtime artifact manifest"
  );
  if (record.version !== 1 || record.kind !== "terminalx.daytona-hardened-runtime-artifacts") {
    throw new TypeError("Daytona runtime artifact manifest kind is invalid");
  }
  const artifacts = exactRecord(
    record.artifacts,
    ["daemon", "runner"],
    "Daytona runtime artifacts"
  );
  const daemon = validateRuntimeArtifact(artifacts.daemon, "daemon", hardenedDaytonaCommit);
  const runner = validateRuntimeArtifact(artifacts.runner, "runner", hardenedDaytonaCommit);
  if (daemon.binaryDigest === runner.binaryDigest) {
    throw new TypeError("Daytona daemon and runner must have distinct binary digests");
  }
  return Object.freeze({
    version: 1,
    kind: record.kind,
    artifacts: Object.freeze({ daemon, runner }),
  });
}

function validateRuntimeArtifact(value, name, hardenedDaytonaCommit) {
  const artifact = exactRecord(
    value,
    ["architecture", "binaryDigest", "operatingSystem", "sourceCommit"],
    `Daytona ${name} artifact`
  );
  if (
    artifact.architecture !== "amd64" ||
    artifact.operatingSystem !== "linux" ||
    gitCommit(artifact.sourceCommit, `${name} sourceCommit`) !== hardenedDaytonaCommit
  ) {
    throw new TypeError(
      `Daytona ${name} artifact identity is not the production linux/amd64 build`
    );
  }
  return Object.freeze({
    architecture: "amd64",
    binaryDigest: digest(artifact.binaryDigest, `${name} binaryDigest`),
    operatingSystem: "linux",
    sourceCommit: hardenedDaytonaCommit,
  });
}

function readSupervisorArchive(archiveBytes) {
  const listing = runTar(["-tzf", "-"], archiveBytes, 8 * 1024 * 1024)
    .toString("utf8")
    .split("\n")
    .filter(Boolean);
  const verbose = runTar(["-tvzf", "-"], archiveBytes, 16 * 1024 * 1024)
    .toString("utf8")
    .split("\n")
    .filter(Boolean);
  if (
    listing.length < 5 ||
    listing.length !== verbose.length ||
    new Set(listing).size !== listing.length
  ) {
    throw new TypeError("Supervisor archive listing is invalid");
  }
  for (let index = 0; index < listing.length; index += 1) {
    const path = listing[index];
    if (
      (path !== "./" && !/^\.\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\/?$/.test(path)) ||
      path.includes("../")
    ) {
      throw new TypeError("Supervisor archive contains an unsafe path");
    }
    const type = verbose[index]?.[0];
    if (type !== "-" && type !== "d") {
      throw new TypeError("Supervisor archive contains a link or special file");
    }
  }
  const required = [
    "./daytona-supervisor-artifact.json",
    "./bin/terminalx-daytona-supervisor",
    "./bin/terminalx-supervisor-relay",
    "./bin/terminalx-assignment-bootstrap",
  ];
  if (required.some((path) => !listing.includes(path))) {
    throw new TypeError("Supervisor archive omits a fixed executable or manifest");
  }
  const manifestBytes = runTar(
    ["-xOzf", "-", "./daytona-supervisor-artifact.json"],
    archiveBytes,
    2 * 1024 * 1024
  );
  assertNoEmbeddedPrivatePem(manifestBytes, "supervisor manifest");
  const executables = {};
  for (const role of [
    "terminalx-daytona-supervisor",
    "terminalx-supervisor-relay",
    "terminalx-assignment-bootstrap",
  ]) {
    const bytes = runTar(["-xOzf", "-", `./bin/${role}`], archiveBytes, 128 * 1024 * 1024);
    assertFixedNodeExecutable(bytes, `supervisor ${role}`);
    assertNoEmbeddedPrivatePem(bytes, `supervisor ${role}`);
    executables[role] = Object.freeze({ bytes, sha256: sha256(bytes) });
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new TypeError("Supervisor artifact manifest is invalid JSON");
  } finally {
    manifestBytes.fill(0);
  }
  return Object.freeze({ manifest, executables: Object.freeze(executables) });
}

function validateSupervisorArtifact(manifest, executables, hardenedDaytonaCommit) {
  const artifact = exactRecord(
    manifest,
    [
      "schemaVersion",
      "kind",
      "source",
      "protocol",
      "fixedExecutables",
      "interpreter",
      "securityBoundary",
      "requiredExternalComponents",
      "files",
    ],
    "supervisor artifact"
  );
  if (artifact.schemaVersion !== 1 || artifact.kind !== "terminalx.daytona-supervisor-build") {
    throw new TypeError("Supervisor artifact kind is invalid");
  }
  const source = exactRecord(
    artifact.source,
    ["terminalxCommit", "daytonaProductionCommit", "daytonaUpstreamBaseCommit"],
    "supervisor source"
  );
  if (
    !GIT_COMMIT.test(source.terminalxCommit) ||
    source.daytonaProductionCommit !== hardenedDaytonaCommit ||
    source.daytonaUpstreamBaseCommit !== productionSource.upstreamBaseCommit
  ) {
    throw new TypeError("Supervisor artifact source does not match the hardened Daytona release");
  }
  if (
    artifact.protocol?.activationRequiresLiveIsolationAttestation !== true ||
    artifact.securityBoundary?.rawPrivateKeyInProtocol !== false ||
    artifact.securityBoundary?.providerSandboxTokenInjected !== false ||
    artifact.securityBoundary?.permissiveEffectFallback !== false ||
    !Array.isArray(artifact.fixedExecutables) ||
    artifact.fixedExecutables.length !== 3
  ) {
    throw new TypeError("Supervisor artifact weakens the fixed runtime boundary");
  }
  const interpreter = exactRecord(
    artifact.interpreter,
    ["path", "ownerUid", "mode", "digestSource", "runnerRemeasureBeforeEveryRootExec"],
    "supervisor interpreter"
  );
  if (
    interpreter.path !== "/usr/local/bin/node" ||
    interpreter.ownerUid !== 0 ||
    interpreter.mode !== 0o555 ||
    interpreter.digestSource !== "/etc/terminalx/sandbox-trust-pins.json#nodeExecutableSha256" ||
    interpreter.runnerRemeasureBeforeEveryRootExec !== true
  ) {
    throw new TypeError("Supervisor artifact does not pin the root interpreter");
  }
  const expected = Object.freeze({
    "root-supervisor": Object.freeze({
      file: "bin/terminalx-daytona-supervisor",
      installPath: "/usr/local/libexec/terminalx/terminalx-daytona-supervisor",
      contextName: "terminalx-daytona-supervisor",
    }),
    "fixed-runner-relay": Object.freeze({
      file: "bin/terminalx-supervisor-relay",
      installPath: "/usr/local/libexec/terminalx/terminalx-supervisor-relay",
      contextName: "terminalx-supervisor-relay",
    }),
    "fixed-assignment-bootstrap": Object.freeze({
      file: "bin/terminalx-assignment-bootstrap",
      installPath: "/usr/local/libexec/terminalx/terminalx-assignment-bootstrap",
      contextName: "terminalx-assignment-bootstrap",
    }),
  });
  const seen = new Set();
  for (const entry of artifact.fixedExecutables) {
    const fixed = exactRecord(
      entry,
      ["role", "file", "installPath", "mode", "bytes", "sha256"],
      "fixed executable"
    );
    const definition = expected[fixed.role];
    if (!definition || seen.has(fixed.role))
      throw new TypeError("Unexpected fixed executable role");
    const measured = executables[definition.contextName];
    if (
      fixed.file !== definition.file ||
      fixed.installPath !== definition.installPath ||
      fixed.mode !== 0o555 ||
      fixed.bytes !== measured.bytes.byteLength ||
      fixed.sha256 !== measured.sha256
    ) {
      throw new TypeError("Fixed supervisor executable does not match its manifest");
    }
    seen.add(fixed.role);
  }
  if (seen.size !== 3) throw new TypeError("Supervisor executable set is incomplete");
  return artifact;
}

function validateBootstrapAuthorityPin(path) {
  const pin = exactRecord(
    JSON.parse(readProtectedFile(path, 64 * 1024, false).toString("utf8")),
    AUTHORITY_PIN_FIELDS,
    "bootstrap authority pin"
  );
  assertNoPrivateMaterial(pin, "bootstrap authority pin");
  if (pin.version !== 1 || pin.kind !== "terminalx.daytona-bootstrap-authority-pin") {
    throw new TypeError("Bootstrap authority pin kind is invalid");
  }
  return Object.freeze({
    version: 1,
    kind: pin.kind,
    issuerKeyId: keyId(pin.issuerKeyId, "bootstrap issuerKeyId"),
    publicKeySpkiPem: canonicalEd25519PublicKey(pin.publicKeySpkiPem, "bootstrap authority"),
  });
}

function readPackageFile(relativePath, maximumBytes) {
  const path = resolve(PACKAGE_ROOT, relativePath);
  if (!path.startsWith(`${PACKAGE_ROOT}/`)) throw new TypeError("Package path escaped");
  return readProtectedFile(path, maximumBytes, false);
}

function readProtectedFile(path, maximumBytes, executable, expectedDigest) {
  let descriptor = -1;
  try {
    const before = lstatSync(path);
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.nlink !== 1 ||
      (before.mode & 0o022) !== 0 ||
      (executable && (before.mode & 0o111) === 0) ||
      before.size < 1 ||
      before.size > maximumBytes ||
      realpathSync.native(path) !== path
    ) {
      throw new TypeError("Build input is not a protected regular file");
    }
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor);
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size ||
      opened.mtimeMs !== before.mtimeMs
    ) {
      throw new TypeError("Build input changed while it was measured");
    }
    const bytes = readFileSync(descriptor);
    if (expectedDigest && sha256(bytes) !== expectedDigest) {
      bytes.fill(0);
      throw new TypeError("Build input digest does not match its release pin");
    }
    return bytes;
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function canonicalSourcePath(value, name) {
  if (typeof value !== "string") throw new TypeError(`${name} path is invalid`);
  const path = resolve(value);
  if (path !== value || realpathSync.native(path) !== path) {
    throw new TypeError(`${name} path must be absolute and symlink-free`);
  }
  return path;
}

function requireEmptyOutput(outputRoot) {
  try {
    const status = statSync(outputRoot);
    if (!status.isDirectory()) throw new TypeError("Build context output is not a directory");
    const entries = spawnSync(
      "find",
      [outputRoot, "-mindepth", "1", "-maxdepth", "1", "-print", "-quit"],
      {
        encoding: "utf8",
        timeout: 5_000,
      }
    );
    if (entries.status !== 0 || entries.stdout.length !== 0) {
      throw new TypeError("Build context output directory must be empty");
    }
    throw new TypeError("Build context output directory must not already exist");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function runTar(arguments_, input, maxBuffer) {
  const result = spawnSync("tar", arguments_, {
    encoding: null,
    input,
    maxBuffer,
    timeout: 30_000,
    env: Object.freeze({ PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" }),
  });
  if (result.status !== 0 || result.signal !== null || result.stderr?.length !== 0) {
    throw new TypeError("Supervisor archive could not be read safely");
  }
  return Buffer.from(result.stdout);
}

function writeExclusive(path, bytes, mode) {
  writeFileSync(path, bytes, { flag: "wx", mode });
  chmodSync(path, mode);
}

function exactRecord(value, fields, name) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== fields.length ||
    Object.keys(value).some((field) => !fields.includes(field))
  ) {
    throw new TypeError(`${name} fields are invalid`);
  }
  return value;
}

function contentImage(value, name) {
  if (typeof value !== "string" || !CONTENT_IMAGE.test(value)) {
    throw new TypeError(`${name} must be a content-addressed OCI reference`);
  }
  return value;
}

function digest(value, name) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${name} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function gitCommit(value, name) {
  if (typeof value !== "string" || !GIT_COMMIT.test(value)) {
    throw new TypeError(`${name} must be an exact Git commit`);
  }
  return value;
}

function keyId(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw new TypeError(`${name} is invalid`);
  }
  return value;
}

function canonicalEd25519PublicKey(value, name) {
  if (typeof value !== "string" || value.includes("PRIVATE KEY")) {
    throw new TypeError(`${name} is not a public key`);
  }
  try {
    const key = createPublicKey(value);
    const canonical = key.export({ type: "spki", format: "pem" }).toString();
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519" || canonical !== value) {
      throw new TypeError();
    }
    return canonical;
  } catch {
    throw new TypeError(`${name} must be a canonical Ed25519 SPKI public key`);
  }
}

function publicKeyDigest(value) {
  return createHash("sha256")
    .update(createPublicKey(value).export({ type: "spki", format: "der" }))
    .digest("hex");
}

function assertNoPrivateMaterial(value, name) {
  const serialized = JSON.stringify(value);
  if (
    PRIVATE_PEM.test(serialized) ||
    Object.keys(value).some((field) => /(?:private|secret|password|token|credential)/i.test(field))
  ) {
    throw new TypeError(`${name} contains forbidden private material`);
  }
}

function assertNoEmbeddedPrivatePem(bytes, name) {
  if (PRIVATE_PEM.test(bytes.toString("latin1"))) {
    throw new TypeError(`${name} contains embedded private-key material`);
  }
}

function assertExecutableFormat(bytes, name, allowFixedNodeShebang) {
  const elf =
    bytes.byteLength >= 4 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46;
  const node =
    allowFixedNodeShebang && bytes.subarray(0, 22).toString("ascii") === "#!/usr/local/bin/node\n";
  if (!elf && !node) throw new TypeError(`${name} has an unsupported executable format`);
}

function assertFixedNodeExecutable(bytes, name) {
  if (bytes.subarray(0, 22).toString("ascii") !== "#!/usr/local/bin/node\n") {
    throw new TypeError(`${name} does not use the pinned Node interpreter`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0))
      throw new TypeError("Non-canonical number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.length !== 4) {
    process.stderr.write("usage: prepare-build-context.mjs <config.json> <new-output-directory>\n");
    process.exitCode = 64;
  } else {
    try {
      prepareBuildContext(process.argv[2], process.argv[3]);
    } catch {
      process.stderr.write("TerminalX sandbox build inputs failed closed\n");
      process.exitCode = 1;
    }
  }
}
