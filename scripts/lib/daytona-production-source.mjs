import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { types as utilTypes } from "node:util";

const SOURCE_FIELDS = Object.freeze([
  "schemaVersion",
  "kind",
  "forkRepository",
  "productionForkCommit",
  "upstreamRepository",
  "upstreamBaseCommit",
]);
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const GITHUB_REPOSITORY =
  /^https:\/\/github\.com\/[a-z0-9](?:[a-z0-9-]{0,38})\/[A-Za-z0-9_.-]{1,100}$/;
const DEFAULT_CONFIGURATION_FILE = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../config/daytona-production-source.json"
);

export function validateDaytonaProductionSource(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError("Daytona production source configuration must be a plain JSON object");
  }
  const fields = Reflect.ownKeys(value);
  if (
    fields.length !== SOURCE_FIELDS.length ||
    fields.some((field) => typeof field !== "string" || !SOURCE_FIELDS.includes(field))
  ) {
    throw new TypeError("Daytona production source configuration has an invalid schema");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    SOURCE_FIELDS.some((field) => {
      const descriptor = descriptors[field];
      return !descriptor?.enumerable || !("value" in descriptor);
    }) ||
    value.schemaVersion !== 1 ||
    value.kind !== "terminalx.daytona-production-source" ||
    typeof value.forkRepository !== "string" ||
    !GITHUB_REPOSITORY.test(value.forkRepository) ||
    typeof value.upstreamRepository !== "string" ||
    !GITHUB_REPOSITORY.test(value.upstreamRepository) ||
    value.forkRepository === value.upstreamRepository ||
    typeof value.productionForkCommit !== "string" ||
    !GIT_COMMIT.test(value.productionForkCommit) ||
    typeof value.upstreamBaseCommit !== "string" ||
    !GIT_COMMIT.test(value.upstreamBaseCommit) ||
    value.productionForkCommit === value.upstreamBaseCommit
  ) {
    throw new TypeError("Daytona production source configuration is invalid");
  }
  return Object.freeze({
    schemaVersion: 1,
    kind: "terminalx.daytona-production-source",
    forkRepository: value.forkRepository,
    productionForkCommit: value.productionForkCommit,
    upstreamRepository: value.upstreamRepository,
    upstreamBaseCommit: value.upstreamBaseCommit,
  });
}

export function loadDaytonaProductionSource(configurationFile = DEFAULT_CONFIGURATION_FILE) {
  const path = resolve(configurationFile);
  const before = lstatSync(path);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    (before.mode & 0o022) !== 0 ||
    before.size < 2 ||
    before.size > 16 * 1024 ||
    realpathSync.native(path) !== path
  ) {
    throw new TypeError("Daytona production source configuration is not a protected file");
  }
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  let bytes;
  try {
    const opened = fstatSync(descriptor);
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size ||
      opened.mtimeMs !== before.mtimeMs
    ) {
      throw new TypeError("Daytona production source configuration changed while loading");
    }
    bytes = readFileSync(descriptor);
    return validateDaytonaProductionSource(JSON.parse(bytes.toString("utf8")));
  } finally {
    bytes?.fill(0);
    closeSync(descriptor);
  }
}

export function daytonaForkRepositorySlug(source) {
  const validated = validateDaytonaProductionSource({ ...source });
  return new URL(validated.forkRepository).pathname.replace(/^\//, "");
}

export const DAYTONA_PRODUCTION_SOURCE_CONFIGURATION_FILE = DEFAULT_CONFIGURATION_FILE;
