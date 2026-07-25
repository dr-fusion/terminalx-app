import { createHash, timingSafeEqual } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, normalize, relative, resolve, sep } from "node:path";
import { types as nodeTypes } from "node:util";
import { DaytonaSupervisorProtocolError } from "./supervisor";

const SHA256 = /^[0-9a-f]{64}$/;
const MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024;

export interface PinnedRootExecutable {
  readonly executableRoot: string;
  readonly executableFile: string;
  readonly executableSha256: string;
  readonly expectedOwnerUid: number;
}

/** Validate, canonicalize and immediately measure one immutable executable. */
export function capturePinnedRootExecutable(value: PinnedRootExecutable): PinnedRootExecutable {
  if (
    typeof value !== "object" ||
    value === null ||
    nodeTypes.isProxy(value) ||
    typeof value.executableRoot !== "string" ||
    !isAbsolute(value.executableRoot) ||
    normalize(value.executableRoot) !== value.executableRoot ||
    typeof value.executableFile !== "string" ||
    !isAbsolute(value.executableFile) ||
    normalize(value.executableFile) !== value.executableFile ||
    typeof value.executableSha256 !== "string" ||
    !SHA256.test(value.executableSha256) ||
    !Number.isSafeInteger(value.expectedOwnerUid) ||
    value.expectedOwnerUid < 0
  ) {
    throw new TypeError();
  }
  const captured = Object.freeze({
    executableRoot: value.executableRoot,
    executableFile: value.executableFile,
    executableSha256: value.executableSha256,
    expectedOwnerUid: value.expectedOwnerUid,
  });
  assertPinnedRootExecutable(captured);
  return captured;
}

/** Re-measure immediately before and after every privileged invocation. */
export function assertPinnedRootExecutable(options: PinnedRootExecutable): void {
  let descriptor = -1;
  try {
    assertProtectedExecutablePath(options);
    if (realpathSync.native(options.executableFile) !== options.executableFile)
      throw new TypeError();
    const pathStat = lstatSync(options.executableFile);
    if (
      pathStat.isSymbolicLink() ||
      !pathStat.isFile() ||
      pathStat.nlink !== 1 ||
      pathStat.uid !== options.expectedOwnerUid ||
      (pathStat.mode & 0o022) !== 0 ||
      (pathStat.mode & 0o111) === 0 ||
      pathStat.size < 1 ||
      pathStat.size > MAX_EXECUTABLE_BYTES
    ) {
      throw new TypeError();
    }
    descriptor = openSync(options.executableFile, fsConstants.O_RDONLY | noFollowFlag());
    const descriptorStat = fstatSync(descriptor);
    if (
      descriptorStat.dev !== pathStat.dev ||
      descriptorStat.ino !== pathStat.ino ||
      descriptorStat.size !== pathStat.size ||
      descriptorStat.mtimeMs !== pathStat.mtimeMs
    ) {
      throw new TypeError();
    }
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    try {
      let position = 0;
      while (position < descriptorStat.size) {
        const count = readSync(
          descriptor,
          buffer,
          0,
          Math.min(buffer.byteLength, descriptorStat.size - position),
          position
        );
        if (count < 1) throw new TypeError();
        hash.update(buffer.subarray(0, count));
        position += count;
      }
    } finally {
      buffer.fill(0);
    }
    const actual = hash.digest();
    const expected = Buffer.from(options.executableSha256, "hex");
    if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) {
      throw new TypeError();
    }
  } catch {
    throw new DaytonaSupervisorProtocolError("not-ready");
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function assertProtectedExecutablePath(options: PinnedRootExecutable): void {
  if (realpathSync.native(options.executableRoot) !== options.executableRoot) throw new TypeError();
  const candidate = relative(options.executableRoot, options.executableFile);
  if (
    candidate.length === 0 ||
    candidate === ".." ||
    candidate.startsWith(`..${sep}`) ||
    isAbsolute(candidate)
  ) {
    throw new TypeError();
  }
  const components = candidate.split(sep);
  components.pop();
  let current = options.executableRoot;
  assertProtectedDirectory(current, options.expectedOwnerUid);
  for (const component of components) {
    current = resolve(current, component);
    assertProtectedDirectory(current, options.expectedOwnerUid);
  }
}

function assertProtectedDirectory(path: string, expectedOwnerUid: number): void {
  const stat = lstatSync(path);
  if (
    stat.isSymbolicLink() ||
    !stat.isDirectory() ||
    stat.uid !== expectedOwnerUid ||
    (stat.mode & 0o022) !== 0
  ) {
    throw new TypeError();
  }
}

function noFollowFlag(): number {
  return fsConstants.O_NOFOLLOW ?? 0;
}
