#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  chmodSync,
  constants,
  lstatSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { open } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CONFIGURATION_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../config/whisper-artifacts.json"
);
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const MODEL_NAME = /^(?:tiny|base|small|medium)(?:\.en)?$|^large-v[123]$|^large-v3-turbo$/;
const MODEL_FILENAME = /^ggml-[a-z0-9.-]+\.bin$/;

function loadConfiguration() {
  const value = JSON.parse(readFileSync(CONFIGURATION_PATH, "utf8"));
  if (
    value?.schemaVersion !== 1 ||
    value?.kind !== "terminalx.whisper-artifacts" ||
    value?.source?.repository !== "https://github.com/ggml-org/whisper.cpp.git" ||
    value?.source?.tag !== "v1.8.6" ||
    !GIT_COMMIT.test(value?.source?.commit ?? "") ||
    value?.modelRepository?.repository !== "https://huggingface.co/ggerganov/whisper.cpp" ||
    !GIT_COMMIT.test(value?.modelRepository?.revision ?? "") ||
    value?.models === null ||
    typeof value?.models !== "object" ||
    Array.isArray(value.models)
  ) {
    throw new Error("Invalid canonical Whisper artifact configuration");
  }
  const names = Object.keys(value.models);
  if (names.length !== 12 || names.some((name) => !MODEL_NAME.test(name))) {
    throw new Error("Invalid canonical Whisper model set");
  }
  for (const name of names) {
    const model = value.models[name];
    if (
      model === null ||
      typeof model !== "object" ||
      Array.isArray(model) ||
      Object.keys(model).sort().join(",") !== "filename,sha256,size" ||
      !MODEL_FILENAME.test(model.filename ?? "") ||
      !SHA256.test(model.sha256 ?? "") ||
      !Number.isSafeInteger(model.size) ||
      model.size <= 0
    ) {
      throw new Error("Invalid canonical Whisper model artifact");
    }
  }
  return value;
}

function sameFileIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

async function inspectFile(filename) {
  const path = resolve(filename);
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
    throw new Error("Artifact must be one regular, non-symbolic-link file");
  }
  if (resolve(realpathSync.native(path)) !== path) {
    throw new Error("Artifact path must be canonical");
  }
  const descriptor = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await descriptor.stat();
    if (!sameFileIdentity(before, opened)) {
      throw new Error("Artifact changed while opening");
    }
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let position = 0;
    for (;;) {
      const { bytesRead } = await descriptor.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await descriptor.stat();
    if (!sameFileIdentity(opened, after) || position !== after.size) {
      throw new Error("Artifact changed while hashing");
    }
    return { sha256: digest.digest("hex"), size: after.size };
  } finally {
    await descriptor.close();
  }
}

function modelMetadata(configuration, name) {
  if (!MODEL_NAME.test(name ?? "") || !Object.hasOwn(configuration.models, name)) {
    throw new Error("Unsupported Whisper model");
  }
  const model = configuration.models[name];
  return {
    name,
    filename: model.filename,
    sha256: model.sha256,
    size: model.size,
    repository: configuration.modelRepository.repository,
    revision: configuration.modelRepository.revision,
    url: `${configuration.modelRepository.repository}/resolve/${configuration.modelRepository.revision}/${model.filename}?download=true`,
  };
}

async function main() {
  const configuration = loadConfiguration();
  const [command, ...args] = process.argv.slice(2);
  if (command === "model" && args.length === 1) {
    const model = modelMetadata(configuration, args[0]);
    process.stdout.write(
      [
        configuration.source.repository,
        configuration.source.tag,
        configuration.source.commit,
        model.repository,
        model.revision,
        model.filename,
        model.sha256,
        String(model.size),
        model.url,
      ].join("\t") + "\n"
    );
    return;
  }
  if (command === "verify-file" && args.length === 3) {
    const [filename, expectedDigest, expectedSizeRaw] = args;
    const expectedSize = Number(expectedSizeRaw);
    if (!SHA256.test(expectedDigest) || !Number.isSafeInteger(expectedSize) || expectedSize <= 0) {
      throw new Error("Invalid expected artifact identity");
    }
    const actual = await inspectFile(filename);
    if (actual.sha256 !== expectedDigest || actual.size !== expectedSize) {
      throw new Error("Artifact identity mismatch");
    }
    return;
  }
  if (command === "write-runtime-manifest" && args.length === 4) {
    const [filename, modelName, binaryPath, modelPath] = args;
    const model = modelMetadata(configuration, modelName);
    const [binaryIdentity, modelIdentity] = await Promise.all([
      inspectFile(binaryPath),
      inspectFile(modelPath),
    ]);
    if (modelIdentity.sha256 !== model.sha256 || modelIdentity.size !== model.size) {
      throw new Error("Model identity mismatch");
    }
    const manifest = {
      schemaVersion: 1,
      kind: "terminalx.whisper-runtime-artifact",
      source: configuration.source,
      platform: process.platform,
      architecture: process.arch,
      binary: {
        kind: "whisper-cli",
        sha256: binaryIdentity.sha256,
        size: binaryIdentity.size,
      },
      model: {
        name: model.name,
        repository: model.repository,
        revision: model.revision,
        filename: model.filename,
        sha256: model.sha256,
        size: model.size,
      },
    };
    writeFileSync(resolve(filename), `${JSON.stringify(manifest)}\n`, { mode: 0o400 });
    chmodSync(resolve(filename), 0o444);
    return;
  }
  throw new Error("Usage: whisper-artifacts.mjs <model|verify-file|write-runtime-manifest> ...");
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "Whisper artifact operation failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
