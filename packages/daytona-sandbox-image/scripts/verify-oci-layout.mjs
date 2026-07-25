#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";

const SHA256_DESCRIPTOR = /^sha256:([0-9a-f]{64})$/;
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const CONTENT_IMAGE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,300}@sha256:[0-9a-f]{64}$/;
const IMAGE_NAME = /^[a-z0-9][a-z0-9._:/-]{0,250}$/;
const PRIVATE_PEM =
  /-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{16,}?-----END (?:ENCRYPTED |RSA |EC |OPENSSH )?PRIVATE KEY-----/;
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const MAX_BLOB_BYTES = 16 * 1024 * 1024 * 1024;

export function verifyOciLayout(
  layoutDirectory,
  contextDirectory,
  outputFile,
  rawBuildMetadataFile,
  normalizedBuildMetadataFile
) {
  const layoutRoot = canonicalDirectory(layoutDirectory);
  const contextRoot = canonicalDirectory(contextDirectory);
  const platform = readSmallText(join(contextRoot, "platform.txt"));
  const imageName = readSmallText(join(contextRoot, "image-name.txt"));
  if (
    (platform !== "linux/amd64" && platform !== "linux/arm64") ||
    !IMAGE_NAME.test(imageName) ||
    imageName.includes("@") ||
    imageName.slice(imageName.lastIndexOf("/") + 1).includes(":")
  ) {
    throw new TypeError("Prepared OCI identity is invalid");
  }
  const arguments_ = readBuildArguments(join(contextRoot, "build-arguments.txt"));
  validateBuildArguments(arguments_);
  const dockerfile = readProtectedFile(join(contextRoot, "Dockerfile"), 512 * 1024).toString(
    "utf8"
  );
  if (!dockerfile.startsWith(`# syntax=${arguments_.BUILDKIT_SYNTAX}\n`)) {
    throw new TypeError("Prepared Dockerfile does not use the pinned frontend");
  }
  const native = exactRecord(
    JSON.parse(
      readProtectedFile(join(contextRoot, "native-hashes.json"), 16 * 1024).toString("utf8")
    ),
    ["isolationProbeSha256", "peerCredentialExecutableSha256", "sandboxInitSha256"]
  );
  if (Object.values(native).some((value) => typeof value !== "string" || !SHA256.test(value))) {
    throw new TypeError("Native helper digest is invalid");
  }
  const layout = JSON.parse(
    readProtectedFile(join(layoutRoot, "oci-layout"), 1024).toString("utf8")
  );
  if (layout.imageLayoutVersion !== "1.0.0") throw new TypeError("Invalid OCI layout version");
  const indexBytes = readProtectedFile(join(layoutRoot, "index.json"), MAX_JSON_BYTES);
  const index = JSON.parse(indexBytes.toString("utf8"));
  if (
    index.schemaVersion !== 2 ||
    index.mediaType !== "application/vnd.oci.image.index.v1+json" ||
    !Array.isArray(index.manifests)
  ) {
    throw new TypeError("Invalid OCI image index");
  }
  const [os, architecture] = platform.split("/");
  const imageDescriptors = index.manifests.filter(
    (descriptor) =>
      descriptor?.platform?.os === os &&
      descriptor?.platform?.architecture === architecture &&
      descriptor?.annotations?.["vnd.docker.reference.type"] !== "attestation-manifest"
  );
  if (imageDescriptors.length !== 1)
    throw new TypeError("OCI output has an ambiguous image manifest");
  const imageDescriptor = validateDescriptor(imageDescriptors[0]);
  if (imageDescriptor.mediaType !== "application/vnd.oci.image.manifest.v1+json") {
    throw new TypeError("OCI image manifest descriptor has an invalid media type");
  }
  const manifest = readJsonBlob(layoutRoot, imageDescriptor);
  if (
    manifest.schemaVersion !== 2 ||
    manifest.mediaType !== "application/vnd.oci.image.manifest.v1+json" ||
    !manifest.config ||
    !Array.isArray(manifest.layers) ||
    manifest.layers.length < 1
  ) {
    throw new TypeError("Invalid OCI image manifest");
  }
  const configDescriptor = validateDescriptor(manifest.config);
  if (configDescriptor.mediaType !== "application/vnd.oci.image.config.v1+json") {
    throw new TypeError("OCI image config descriptor has an invalid media type");
  }
  for (const layer of manifest.layers) {
    if (
      typeof layer?.mediaType !== "string" ||
      !/^application\/vnd\.oci\.image\.layer\.v1\.tar(?:\+(?:gzip|zstd))?$/.test(layer.mediaType)
    ) {
      throw new TypeError("OCI image layer has an invalid media type");
    }
    validateDescriptorAndBlob(layoutRoot, layer);
  }
  const imageConfiguration = readJsonBlob(layoutRoot, configDescriptor);
  validateImageConfiguration(
    imageConfiguration,
    arguments_,
    native,
    architecture,
    os,
    manifest.layers.length
  );
  const imageIndexDigest = `sha256:${sha256(indexBytes)}`;
  const normalizedBuildMetadata = validateBuildMetadata(
    rawBuildMetadataFile,
    imageIndexDigest,
    indexBytes.byteLength,
    imageDescriptor,
    configDescriptor,
    arguments_.SOURCE_DATE_EPOCH
  );

  const predicateTypes = new Set();
  const attestationDescriptors = index.manifests.filter(
    (descriptor) =>
      descriptor?.annotations?.["vnd.docker.reference.type"] === "attestation-manifest"
  );
  if (
    attestationDescriptors.length < 1 ||
    imageDescriptors.length + attestationDescriptors.length !== index.manifests.length
  ) {
    throw new TypeError("OCI output has missing or unrelated manifests");
  }
  for (const descriptor of attestationDescriptors) {
    if (
      descriptor?.platform?.os !== "unknown" ||
      descriptor?.platform?.architecture !== "unknown" ||
      descriptor?.annotations?.["vnd.docker.reference.digest"] !== imageDescriptor.digest ||
      descriptor?.mediaType !== "application/vnd.oci.image.manifest.v1+json"
    ) {
      throw new TypeError("Attestation manifest is not bound to the image manifest");
    }
    const attestationManifest = readJsonBlob(layoutRoot, validateDescriptor(descriptor));
    if (
      attestationManifest.schemaVersion !== 2 ||
      attestationManifest.mediaType !== "application/vnd.oci.image.manifest.v1+json" ||
      attestationManifest.artifactType !== "application/vnd.docker.attestation.manifest.v1+json" ||
      !descriptorMatches(attestationManifest.subject, imageDescriptor) ||
      !attestationManifest.config ||
      !Array.isArray(attestationManifest.layers) ||
      attestationManifest.layers.length < 1
    ) {
      throw new TypeError("Invalid attestation manifest");
    }
    const attestationConfigDescriptor = validateDescriptor(attestationManifest.config);
    if (attestationConfigDescriptor.mediaType !== "application/vnd.oci.empty.v1+json") {
      throw new TypeError("Attestation manifest does not use the OCI empty config");
    }
    const attestationConfig = readJsonBlob(layoutRoot, attestationConfigDescriptor);
    if (
      typeof attestationConfig !== "object" ||
      attestationConfig === null ||
      Array.isArray(attestationConfig) ||
      Object.keys(attestationConfig).length !== 0
    ) {
      throw new TypeError("Attestation manifest config is not empty");
    }
    for (const layer of attestationManifest.layers) {
      const validated = validateDescriptor(layer);
      if (validated.mediaType !== "application/vnd.in-toto+json") {
        throw new TypeError("Attestation layer is not an in-toto statement");
      }
      const bytes = readBlob(layoutRoot, validated, MAX_JSON_BYTES);
      if (PRIVATE_PEM.test(bytes.toString("latin1"))) {
        throw new TypeError("Attestation contains private-key material");
      }
      let statement;
      try {
        statement = JSON.parse(bytes.toString("utf8"));
      } catch {
        throw new TypeError("Attestation layer is not valid JSON");
      }
      const predicateType = validateAttestationStatement(
        statement,
        validated,
        imageDescriptor.digest,
        arguments_
      );
      if (predicateType !== null) predicateTypes.add(predicateType);
    }
  }
  const predicates = [...predicateTypes].sort();
  if (
    !predicateTypes.has("https://spdx.dev/Document") ||
    !predicateTypes.has("https://slsa.dev/provenance/v1")
  ) {
    throw new TypeError("OCI output must contain image-bound SPDX and SLSA v1 attestations");
  }

  const release = Object.freeze({
    schemaVersion: 1,
    kind: "terminalx.daytona-sandbox-image-build",
    imageName,
    platform,
    dockerfileFrontendImage: arguments_.BUILDKIT_SYNTAX,
    imageIndexDigest,
    imageManifestDigest: imageDescriptor.digest,
    imageConfigDigest: configDescriptor.digest,
    dockerImageId: configDescriptor.digest,
    sourceDateEpoch: Number(arguments_.SOURCE_DATE_EPOCH),
    attestations: Object.freeze(predicates),
    labels: Object.freeze({ ...imageConfiguration.config.Labels }),
  });
  writeFileSync(resolve(outputFile), `${JSON.stringify(release, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o644,
  });
  writeFileSync(
    resolve(normalizedBuildMetadataFile),
    `${JSON.stringify(normalizedBuildMetadata, null, 2)}\n`,
    { encoding: "utf8", flag: "wx", mode: 0o644 }
  );
  indexBytes.fill(0);
  return release;
}

function validateBuildMetadata(
  rawFile,
  imageIndexDigest,
  imageIndexSize,
  imageDescriptor,
  configDescriptor,
  sourceDateEpoch
) {
  const rawBytes = readProtectedFile(rawFile, MAX_JSON_BYTES);
  try {
    if (PRIVATE_PEM.test(rawBytes.toString("latin1"))) {
      throw new TypeError("Build metadata contains private-key material");
    }
    const metadata = JSON.parse(rawBytes.toString("utf8"));
    const descriptor = metadata?.["containerimage.descriptor"];
    const outputDigest = metadata?.["containerimage.digest"];
    const expectedDescriptor =
      outputDigest === imageIndexDigest
        ? {
            digest: imageIndexDigest,
            mediaType: "application/vnd.oci.image.index.v1+json",
            size: imageIndexSize,
          }
        : {
            digest: imageDescriptor.digest,
            mediaType: imageDescriptor.mediaType,
            size: imageDescriptor.size,
          };
    if (
      typeof metadata !== "object" ||
      metadata === null ||
      Array.isArray(metadata) ||
      metadata["containerimage.config.digest"] !== configDescriptor.digest ||
      (outputDigest !== imageIndexDigest && outputDigest !== imageDescriptor.digest) ||
      descriptor?.digest !== expectedDescriptor.digest ||
      descriptor?.mediaType !== expectedDescriptor.mediaType ||
      descriptor?.size !== expectedDescriptor.size ||
      (descriptor.annotations?.["config.digest"] !== undefined &&
        descriptor.annotations["config.digest"] !== configDescriptor.digest)
    ) {
      throw new TypeError("Build metadata does not describe the verified OCI output");
    }
    return Object.freeze({
      schemaVersion: 1,
      kind: "terminalx.daytona-sandbox-buildkit-metadata",
      imageIndexDigest,
      imageManifestDigest: imageDescriptor.digest,
      imageConfigDigest: configDescriptor.digest,
      sourceDateEpoch: Number(sourceDateEpoch),
    });
  } finally {
    rawBytes.fill(0);
  }
}

function validateAttestationStatement(statement, layer, imageManifestDigest, arguments_) {
  if (
    layer.mediaType !== "application/vnd.in-toto+json" ||
    (statement?._type !== "https://in-toto.io/Statement/v1" &&
      statement?._type !== "https://in-toto.io/Statement/v0.1") ||
    typeof statement.predicateType !== "string" ||
    layer.annotations?.["in-toto.io/predicate-type"] !== statement.predicateType ||
    !Array.isArray(statement.subject) ||
    !statement.subject.some(
      (subject) =>
        typeof subject?.name === "string" &&
        subject.name.length > 0 &&
        `sha256:${subject?.digest?.sha256}` === imageManifestDigest
    ) ||
    typeof statement.predicate !== "object" ||
    statement.predicate === null ||
    Array.isArray(statement.predicate)
  ) {
    throw new TypeError("Attestation statement is not bound to the image manifest");
  }
  const predicate = statement.predicate;
  if (statement.predicateType === "https://spdx.dev/Document") {
    if (
      predicate.SPDXID !== "SPDXRef-DOCUMENT" ||
      typeof predicate.spdxVersion !== "string" ||
      !/^SPDX-2\.[0-9]+$/.test(predicate.spdxVersion) ||
      !Array.isArray(predicate.packages) ||
      predicate.packages.length < 1 ||
      predicate.packages.some(
        (entry) =>
          typeof entry?.SPDXID !== "string" ||
          !entry.SPDXID.startsWith("SPDXRef-") ||
          typeof entry?.name !== "string" ||
          entry.name.length < 1
      ) ||
      predicate.dataLicense !== "CC0-1.0" ||
      typeof predicate.name !== "string" ||
      predicate.name.length < 1 ||
      typeof predicate.creationInfo?.created !== "string" ||
      !Number.isFinite(Date.parse(predicate.creationInfo.created)) ||
      !Array.isArray(predicate.creationInfo.creators) ||
      predicate.creationInfo.creators.length < 1 ||
      typeof predicate.documentNamespace !== "string" ||
      predicate.documentNamespace.length < 1
    ) {
      throw new TypeError("SPDX attestation is incomplete");
    }
    return statement.predicateType;
  }
  if (statement.predicateType === "https://slsa.dev/provenance/v1") {
    validateMaxSlsaProvenance(predicate, arguments_);
    return statement.predicateType;
  }
  return null;
}

function validateMaxSlsaProvenance(predicate, arguments_) {
  const definition = predicate.buildDefinition;
  const configSource = definition?.externalParameters?.configSource;
  const request = definition?.externalParameters?.request;
  const requestArguments = request?.args;
  const internal = definition?.internalParameters;
  const metadata = predicate.runDetails?.metadata;
  if (
    definition?.buildType !==
      "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md" ||
    typeof request !== "object" ||
    request === null ||
    Array.isArray(request) ||
    request.frontend !== "gateway.v0" ||
    typeof requestArguments !== "object" ||
    requestArguments === null ||
    Array.isArray(requestArguments) ||
    requestArguments.source !== arguments_.BUILDKIT_SYNTAX ||
    requestArguments.target !== "terminalx-sandbox" ||
    !Array.isArray(request.locals) ||
    request.locals.length < 1 ||
    !Array.isArray(request.secrets) ||
    request.secrets.length !== 0 ||
    !Array.isArray(request.ssh) ||
    request.ssh.length !== 0 ||
    !Array.isArray(internal?.buildConfig?.llbDefinition) ||
    internal.buildConfig.llbDefinition.length < 1 ||
    !Array.isArray(definition.resolvedDependencies) ||
    typeof predicate.runDetails?.builder?.id !== "string" ||
    predicate.runDetails.builder.id.length < 1 ||
    typeof metadata !== "object" ||
    metadata === null ||
    metadata.buildkit_hermetic !== true ||
    metadata.buildkit_reproducible !== true ||
    metadata.buildkit_completeness?.request !== true ||
    configSource?.path !== "Dockerfile" ||
    typeof metadata.buildkit_metadata?.source !== "object" ||
    metadata.buildkit_metadata.source === null ||
    typeof metadata.buildkit_metadata?.layers !== "object" ||
    metadata.buildkit_metadata.layers === null
  ) {
    throw new TypeError("SLSA provenance is not hermetic maximum-mode BuildKit provenance");
  }
  for (const [field, expected] of Object.entries(arguments_)) {
    if (field === "BUILDKIT_SYNTAX") continue;
    if (requestArguments[`build-arg:${field}`] !== expected) {
      throw new TypeError("SLSA provenance build arguments do not match the release inputs");
    }
  }
  const materialDigests = new Set();
  for (const dependency of definition.resolvedDependencies) {
    if (typeof dependency?.digest?.sha256 === "string") {
      materialDigests.add(dependency.digest.sha256);
    }
  }
  for (const field of ["BUILDKIT_SYNTAX", "TERMINALX_RUNTIME_IMAGE", "TERMINALX_TOOLCHAIN_IMAGE"]) {
    const expected = /@sha256:([0-9a-f]{64})$/.exec(arguments_[field])?.[1];
    if (!expected || !materialDigests.has(expected)) {
      throw new TypeError("SLSA provenance omits a content-addressed build material");
    }
  }
}

function validateImageConfiguration(
  configuration,
  arguments_,
  native,
  architecture,
  os,
  layerCount
) {
  const config = configuration?.config;
  if (typeof config !== "object" || config === null || Array.isArray(config)) {
    throw new TypeError("OCI image configuration is absent");
  }
  if (
    configuration.architecture !== architecture ||
    configuration.os !== os ||
    !Array.isArray(configuration.history) ||
    configuration.rootfs?.type !== "layers" ||
    !Array.isArray(configuration.rootfs.diff_ids) ||
    configuration.rootfs.diff_ids.length !== layerCount ||
    configuration.rootfs.diff_ids.some((digest) => !SHA256_DESCRIPTOR.test(digest)) ||
    new Date(configuration.created).getTime() !== Number(arguments_.SOURCE_DATE_EPOCH) * 1000 ||
    PRIVATE_PEM.test(JSON.stringify(configuration)) ||
    config.User !== "0" ||
    config.WorkingDir !== "/home/terminalx" ||
    !Array.isArray(config.Entrypoint) ||
    config.Entrypoint.length !== 1 ||
    config.Entrypoint[0] !== "/usr/local/bin/terminalx-sandbox-init" ||
    !Array.isArray(config.Cmd) ||
    config.Cmd.length !== 0 ||
    config.StopSignal !== "SIGTERM" ||
    !Array.isArray(config.Shell) ||
    config.Shell.length !== 3 ||
    config.Shell[0] !== "/bin/sh" ||
    config.Shell[1] !== "-eu" ||
    config.Shell[2] !== "-c" ||
    (config.Volumes && Object.keys(config.Volumes).length !== 0) ||
    (config.ExposedPorts && Object.keys(config.ExposedPorts).length !== 0) ||
    config.Healthcheck != null ||
    (config.OnBuild && config.OnBuild.length !== 0)
  ) {
    throw new TypeError("OCI image exposes an executable or persistence side channel");
  }
  if (!Array.isArray(config.Env) || config.Env.length !== 0) {
    throw new TypeError("OCI image must not inherit environment variables");
  }
  for (const entry of config.Env) {
    if (
      typeof entry !== "string" ||
      /(?:PRIVATE|SECRET|TOKEN|PASSWORD|CREDENTIAL)/i.test(entry.split("=", 1)[0]) ||
      PRIVATE_PEM.test(entry)
    ) {
      throw new TypeError("OCI image environment contains private material");
    }
  }
  const expectedLabels = Object.freeze({
    "io.terminalx.sandbox.profile": "v1",
    "io.terminalx.supervisor-relay.sha256": arguments_.TERMINALX_SUPERVISOR_RELAY_SHA256,
    "io.terminalx.assignment-bootstrap.sha256": arguments_.TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256,
    "io.terminalx.node.sha256": arguments_.TERMINALX_NODE_SHA256,
    "io.terminalx.deployment-binding-installer.sha256":
      arguments_.TERMINALX_DEPLOYMENT_BINDING_INSTALL_SHA256,
    "io.terminalx.isolation-probe.sha256": native.isolationProbeSha256,
    "io.terminalx.sandbox-init.sha256": native.sandboxInitSha256,
    "io.terminalx.peercred.sha256": native.peerCredentialExecutableSha256,
    "io.terminalx.daytona-daemon.sha256": arguments_.TERMINALX_DAYTONA_DAEMON_SHA256,
    "io.terminalx.effect-enforcer.sha256": arguments_.TERMINALX_EFFECT_ENFORCER_SHA256,
    "io.terminalx.supervisor.sha256": arguments_.TERMINALX_SUPERVISOR_SHA256,
    "io.terminalx.supervisor-artifact.sha256": arguments_.TERMINALX_SUPERVISOR_ARTIFACT_SHA256,
    "io.terminalx.daytona-source.commit": arguments_.TERMINALX_DAYTONA_SOURCE_COMMIT,
    "org.opencontainers.image.revision": arguments_.TERMINALX_SOURCE_COMMIT,
    "io.terminalx.source-date-epoch": arguments_.SOURCE_DATE_EPOCH,
  });
  const labels = config.Labels;
  if (typeof labels !== "object" || labels === null || Array.isArray(labels)) {
    throw new TypeError("OCI image labels are absent");
  }
  for (const [key, value] of Object.entries(expectedLabels)) {
    if (labels[key] !== value) throw new TypeError(`OCI image label mismatch: ${key}`);
  }
  for (const [key, value] of Object.entries(labels)) {
    if (
      /(?:private|secret|token|password|credential)/i.test(key) ||
      typeof value !== "string" ||
      PRIVATE_PEM.test(value)
    ) {
      throw new TypeError("OCI image label contains private material");
    }
  }
}

function readBuildArguments(path) {
  const result = {};
  for (const line of readSmallText(path, 64 * 1024, true).split("\n")) {
    if (!line) continue;
    const separator = line.indexOf("=");
    if (separator < 1) throw new TypeError("Invalid build argument record");
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (!/^[A-Z][A-Z0-9_]+$/.test(key) || value.length < 1 || key in result) {
      throw new TypeError("Invalid build argument record");
    }
    result[key] = value;
  }
  return Object.freeze(result);
}

function validateBuildArguments(value) {
  const fields = [
    "BUILDKIT_SYNTAX",
    "TERMINALX_RUNTIME_IMAGE",
    "TERMINALX_TOOLCHAIN_IMAGE",
    "SOURCE_DATE_EPOCH",
    "TERMINALX_SUPERVISOR_ARTIFACT_SHA256",
    "TERMINALX_SUPERVISOR_SHA256",
    "TERMINALX_SUPERVISOR_RELAY_SHA256",
    "TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256",
    "TERMINALX_DAYTONA_DAEMON_SHA256",
    "TERMINALX_EFFECT_ENFORCER_SHA256",
    "TERMINALX_NODE_SHA256",
    "TERMINALX_DEPLOYMENT_BINDING_INSTALL_SHA256",
    "TERMINALX_SOURCE_COMMIT",
    "TERMINALX_DAYTONA_SOURCE_COMMIT",
  ];
  if (
    Object.keys(value).length !== fields.length ||
    Object.keys(value).some((field) => !fields.includes(field)) ||
    !CONTENT_IMAGE.test(value.BUILDKIT_SYNTAX) ||
    !CONTENT_IMAGE.test(value.TERMINALX_RUNTIME_IMAGE) ||
    !CONTENT_IMAGE.test(value.TERMINALX_TOOLCHAIN_IMAGE) ||
    new Set([value.BUILDKIT_SYNTAX, value.TERMINALX_RUNTIME_IMAGE, value.TERMINALX_TOOLCHAIN_IMAGE])
      .size !== 3 ||
    !/^(?:0|[1-9][0-9]{0,15})$/.test(value.SOURCE_DATE_EPOCH) ||
    !Number.isSafeInteger(Number(value.SOURCE_DATE_EPOCH)) ||
    !GIT_COMMIT.test(value.TERMINALX_SOURCE_COMMIT) ||
    !GIT_COMMIT.test(value.TERMINALX_DAYTONA_SOURCE_COMMIT)
  ) {
    throw new TypeError("OCI build arguments are invalid");
  }
  for (const field of fields.filter((field) => field.endsWith("SHA256"))) {
    if (!SHA256.test(value[field])) throw new TypeError("OCI build digest is invalid");
  }
}

function validateDescriptorAndBlob(layoutRoot, value) {
  const descriptor = validateDescriptor(value);
  const match = SHA256_DESCRIPTOR.exec(descriptor.digest);
  if (!match) throw new TypeError("Invalid OCI layer digest");
  assertBlobDigest(
    join(layoutRoot, "blobs", "sha256", match[1]),
    descriptor.size,
    descriptor.digest
  );
  return descriptor;
}

function validateDescriptor(value) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    typeof value.digest !== "string" ||
    !SHA256_DESCRIPTOR.test(value.digest) ||
    !Number.isSafeInteger(value.size) ||
    value.size < 1 ||
    value.size > MAX_BLOB_BYTES ||
    typeof value.mediaType !== "string"
  ) {
    throw new TypeError("Invalid OCI descriptor");
  }
  return value;
}

function descriptorMatches(value, expected) {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    value.mediaType === expected.mediaType &&
    value.digest === expected.digest &&
    value.size === expected.size
  );
}

function readJsonBlob(layoutRoot, descriptor) {
  const bytes = readBlob(layoutRoot, descriptor, MAX_JSON_BYTES);
  try {
    return JSON.parse(bytes.toString("utf8"));
  } finally {
    bytes.fill(0);
  }
}

function readBlob(layoutRoot, descriptor, maximumBytes) {
  const match = SHA256_DESCRIPTOR.exec(descriptor.digest);
  if (!match || descriptor.size > maximumBytes) throw new TypeError("Invalid OCI blob digest");
  const bytes = readProtectedFile(join(layoutRoot, "blobs", "sha256", match[1]), maximumBytes);
  if (bytes.byteLength !== descriptor.size || `sha256:${sha256(bytes)}` !== descriptor.digest) {
    bytes.fill(0);
    throw new TypeError("OCI blob does not match its descriptor");
  }
  return bytes;
}

function assertBlobDigest(path, expectedSize, expectedDigest) {
  const status = lstatSync(path);
  let descriptor = -1;
  const chunk = Buffer.alloc(1024 * 1024);
  if (
    !status.isFile() ||
    status.isSymbolicLink() ||
    status.nlink !== 1 ||
    status.size !== expectedSize ||
    status.size < 1 ||
    status.size > MAX_BLOB_BYTES ||
    realpathSync.native(path) !== path
  ) {
    throw new TypeError("OCI layer is not a protected regular file");
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
      throw new TypeError("OCI layer changed while it was measured");
    }
    const hash = createHash("sha256");
    let offset = 0;
    while (offset < opened.size) {
      const count = readSync(
        descriptor,
        chunk,
        0,
        Math.min(chunk.byteLength, opened.size - offset),
        offset
      );
      if (count < 1) throw new TypeError("OCI layer read failed");
      hash.update(chunk.subarray(0, count));
      offset += count;
    }
    if (`sha256:${hash.digest("hex")}` !== expectedDigest) {
      throw new TypeError("OCI layer digest mismatch");
    }
  } finally {
    chunk.fill(0);
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function canonicalDirectory(path) {
  const absolute = resolve(path);
  const status = lstatSync(absolute);
  if (
    !status.isDirectory() ||
    status.isSymbolicLink() ||
    realpathSync.native(absolute) !== absolute
  ) {
    throw new TypeError("OCI path is not a canonical directory");
  }
  return absolute;
}

function readSmallText(path, maximumBytes = 4096, preserveNewlines = false) {
  const value = readProtectedFile(path, maximumBytes).toString("utf8");
  return preserveNewlines ? value.trimEnd() : value.trim();
}

function readProtectedFile(path, maximumBytes) {
  const status = lstatSync(path);
  let descriptor = -1;
  if (
    !status.isFile() ||
    status.isSymbolicLink() ||
    status.nlink !== 1 ||
    status.size < 1 ||
    status.size > maximumBytes ||
    realpathSync.native(path) !== path
  ) {
    throw new TypeError("OCI file is not a protected regular file");
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
      throw new TypeError("OCI file changed while it was measured");
    }
    return readFileSync(descriptor);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function exactRecord(value, fields) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    Object.keys(value).some((field) => !fields.includes(field))
  ) {
    throw new TypeError("Invalid exact record");
  }
  return value;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv.length !== 7) {
    process.stderr.write(
      "usage: verify-oci-layout.mjs <oci-layout> <build-context> <release.json> <raw-build-metadata.json> <normalized-build-metadata.json>\n"
    );
    process.exitCode = 64;
  } else {
    try {
      verifyOciLayout(
        process.argv[2],
        process.argv[3],
        process.argv[4],
        process.argv[5],
        process.argv[6]
      );
    } catch {
      process.stderr.write("TerminalX OCI output verification failed closed\n");
      process.exitCode = 1;
    }
  }
}
