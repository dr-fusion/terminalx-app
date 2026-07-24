import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  type BigIntStats,
} from "node:fs";
import { isAbsolute, parse, relative, resolve, sep } from "node:path";

const PRIVATE_DIRECTORY_MODES = new Set([BigInt(0o500), BigInt(0o700)]);
const PRIVATE_FILE_MODES = new Set([BigInt(0o400), BigInt(0o600)]);

export interface ReadTrustedConfigurationFileOptions {
  /**
   * Absolute canonical path to a private operator-owned 0500/0700 configuration
   * directory. This is an explicit trust root, not an arbitrary browser
   * workspace. Composition may bind it only from a separately validated
   * TERMINUS_ROOT or, preferably, a stricter dedicated configuration root.
   */
  readonly trustedConfigurationRoot: unknown;
  /** Absolute canonical path to a file strictly below the trust root. */
  readonly filePath: unknown;
  readonly minimumBytes: number;
  readonly maximumBytes: number;
}

/** Generic internal failure: paths and metadata are intentionally omitted. */
export class TrustedConfigurationFileError extends Error {
  constructor() {
    super("Trusted configuration file is unavailable");
    this.name = "TrustedConfigurationFileError";
  }
}

interface PathSnapshot {
  readonly path: string;
  readonly stat: BigIntStats;
  readonly insideTrustRoot: boolean;
}

interface TrustedPathSnapshot {
  readonly components: readonly PathSnapshot[];
  readonly file: BigIntStats;
}

/**
 * Read one bounded, private configuration file while defending the complete
 * pathname, not only the final file descriptor. All path components are
 * checked before and after the read; an inode, ownership, mode, link-count,
 * size, or timestamp change makes the operation fail closed.
 */
export function readTrustedConfigurationFile(
  unsafeOptions: ReadTrustedConfigurationFileOptions
): Buffer {
  return readTrustedConfigurationFileInternal(unsafeOptions);
}

/** @internal Deterministic replacement-race seam used only by this module's tests. */
export function readTrustedConfigurationFileWithRaceHookForTest(
  unsafeOptions: ReadTrustedConfigurationFileOptions,
  afterRead: () => void
): Buffer {
  if (process.env.NODE_ENV !== "test" || typeof afterRead !== "function") unavailable();
  return readTrustedConfigurationFileInternal(unsafeOptions, afterRead);
}

function readTrustedConfigurationFileInternal(
  unsafeOptions: ReadTrustedConfigurationFileOptions,
  afterRead?: () => void
): Buffer {
  if (
    typeof fsConstants.O_NOFOLLOW !== "number" ||
    typeof process.geteuid !== "function" ||
    typeof unsafeOptions !== "object" ||
    unsafeOptions === null
  ) {
    unavailable();
  }

  const { trustedConfigurationRoot, filePath, minimumBytes, maximumBytes } = unsafeOptions;
  if (
    !Number.isSafeInteger(minimumBytes) ||
    !Number.isSafeInteger(maximumBytes) ||
    minimumBytes < 1 ||
    maximumBytes < minimumBytes
  ) {
    unavailable();
  }
  const root = canonicalAbsolutePath(trustedConfigurationRoot);
  const target = canonicalAbsolutePath(filePath);
  if (!isStrictDescendant(root, target)) unavailable();

  let before: TrustedPathSnapshot;
  try {
    before = inspectTrustedPath(root, target, minimumBytes, maximumBytes);
    if (realpathSync.native(root) !== root || realpathSync.native(target) !== target) unavailable();
  } catch (error) {
    if (error instanceof TrustedConfigurationFileError) throw error;
    unavailable();
  }

  let descriptor: number;
  try {
    descriptor = openSync(target, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch {
    unavailable();
  }

  let workingBytes: Buffer | undefined;
  let result: Buffer | undefined;
  let failed = false;
  try {
    const descriptorBefore = fstatSync(descriptor, { bigint: true });
    if (!sameSnapshot(before.file, descriptorBefore)) unavailable();

    const expectedBytes = Number(descriptorBefore.size);
    workingBytes = Buffer.alloc(expectedBytes + 1);
    let offset = 0;
    while (offset < workingBytes.byteLength) {
      const count = readSync(
        descriptor,
        workingBytes,
        offset,
        workingBytes.byteLength - offset,
        null
      );
      if (count === 0) break;
      offset += count;
    }
    if (offset !== expectedBytes) unavailable();
    afterRead?.();

    const descriptorAfter = fstatSync(descriptor, { bigint: true });
    const after = inspectTrustedPath(root, target, minimumBytes, maximumBytes);
    if (
      realpathSync.native(root) !== root ||
      realpathSync.native(target) !== target ||
      !sameSnapshot(descriptorBefore, descriptorAfter) ||
      !sameSnapshot(descriptorAfter, after.file) ||
      !samePathSnapshots(before.components, after.components)
    ) {
      unavailable();
    }
    result = Buffer.from(workingBytes.subarray(0, expectedBytes));
  } catch (error) {
    failed = true;
    if (error instanceof TrustedConfigurationFileError) throw error;
    unavailable();
  } finally {
    workingBytes?.fill(0);
    try {
      closeSync(descriptor);
    } catch {
      failed = true;
    }
  }
  if (failed || result === undefined) {
    result?.fill(0);
    unavailable();
  }
  return result;
}

function canonicalAbsolutePath(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\0") ||
    !isAbsolute(value) ||
    resolve(value) !== value
  ) {
    unavailable();
  }
  return value;
}

function isStrictDescendant(root: string, target: string): boolean {
  const candidate = relative(root, target);
  return (
    candidate.length > 0 &&
    candidate !== ".." &&
    !candidate.startsWith(`..${sep}`) &&
    !isAbsolute(candidate)
  );
}

function inspectTrustedPath(
  root: string,
  target: string,
  minimumBytes: number,
  maximumBytes: number
): TrustedPathSnapshot {
  const rootComponents = pathComponents(root);
  const targetComponents = pathComponents(target);
  const snapshots: PathSnapshot[] = [];
  let insideTrustRoot = false;
  const getEffectiveUid = process.geteuid;
  if (typeof getEffectiveUid !== "function") unavailable();
  const effectiveUid = BigInt(getEffectiveUid());

  for (let index = 0; index < targetComponents.length; index += 1) {
    const component = targetComponents[index];
    if (component === undefined) unavailable();
    const stat = lstatSync(component, { bigint: true });
    const isTarget = index === targetComponents.length - 1;
    if (stat.isSymbolicLink()) unavailable();
    if (!isTarget && !stat.isDirectory()) unavailable();
    if (component === root) insideTrustRoot = true;
    if (insideTrustRoot && !isTarget) assertPrivateDirectory(stat, effectiveUid);
    snapshots.push({ path: component, stat, insideTrustRoot });
  }
  if (!insideTrustRoot || rootComponents.at(-1) !== root) unavailable();

  const file = snapshots.at(-1)?.stat;
  if (file === undefined) unavailable();
  const mode = file.mode & BigInt(0o777);
  if (
    !file.isFile() ||
    file.uid !== effectiveUid ||
    file.nlink !== BigInt(1) ||
    !PRIVATE_FILE_MODES.has(mode) ||
    (file.mode & BigInt(0o7000)) !== BigInt(0) ||
    file.size < BigInt(minimumBytes) ||
    file.size > BigInt(maximumBytes)
  ) {
    unavailable();
  }
  return { components: snapshots, file };
}

function assertPrivateDirectory(stat: BigIntStats, effectiveUid: bigint): void {
  const mode = stat.mode & BigInt(0o777);
  if (
    !stat.isDirectory() ||
    stat.uid !== effectiveUid ||
    !PRIVATE_DIRECTORY_MODES.has(mode) ||
    (stat.mode & BigInt(0o7000)) !== BigInt(0)
  ) {
    unavailable();
  }
}

function pathComponents(value: string): readonly string[] {
  const root = parse(value).root;
  if (root.length === 0) unavailable();
  const components = [root];
  let current = root;
  for (const segment of value.slice(root.length).split(sep)) {
    if (segment.length === 0) continue;
    current = current === root ? `${root}${segment}` : `${current}${sep}${segment}`;
    components.push(current);
  }
  return components;
}

function samePathSnapshots(left: readonly PathSnapshot[], right: readonly PathSnapshot[]): boolean {
  if (left.length !== right.length) return false;
  return left.every((entry, index) => {
    const candidate = right[index];
    return (
      candidate !== undefined &&
      entry.path === candidate.path &&
      entry.insideTrustRoot === candidate.insideTrustRoot &&
      (entry.insideTrustRoot
        ? sameSnapshot(entry.stat, candidate.stat)
        : samePathIdentity(entry.stat, candidate.stat))
    );
  });
}

function samePathIdentity(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.gid === right.gid
  );
}

function sameSnapshot(left: BigIntStats, right: BigIntStats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.uid === right.uid &&
    left.gid === right.gid &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}

function unavailable(): never {
  throw new TrustedConfigurationFileError();
}
