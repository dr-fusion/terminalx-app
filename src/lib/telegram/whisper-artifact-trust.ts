import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import type { Stats } from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import artifactConfiguration from "../../../config/whisper-artifacts.json";

const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const MAX_MANIFEST_BYTES = 32 * 1024;
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;

interface FileIdentity {
  readonly dev: number;
  readonly ino: number;
  readonly size: number;
  readonly mtimeMs: number;
  readonly ctimeMs: number;
}

interface RuntimeManifest {
  readonly schemaVersion: 1;
  readonly kind: "terminalx.whisper-runtime-artifact";
  readonly source: {
    readonly repository: string;
    readonly tag: string;
    readonly commit: string;
  };
  readonly platform: string;
  readonly architecture: string;
  readonly binary: {
    readonly kind: "whisper-cli";
    readonly sha256: string;
    readonly size: number;
  };
  readonly model: {
    readonly name: string;
    readonly repository: string;
    readonly revision: string;
    readonly filename: string;
    readonly sha256: string;
    readonly size: number;
  };
}

interface WhisperArtifactAuthority {
  readonly source: {
    readonly repository: string;
    readonly tag: string;
    readonly commit: string;
  };
  readonly modelRepository: {
    readonly repository: string;
    readonly revision: string;
  };
  readonly models: Readonly<
    Record<string, { readonly filename: string; readonly sha256: string; readonly size: number }>
  >;
}

export interface VerifiedWhisperRuntimeArtifacts {
  readonly binaryPath: string;
  readonly modelPath: string;
  readonly modelName: string;
}

const verifiedArtifactCache = new Map<
  string,
  { readonly expected: string; readonly identity: FileIdentity }
>();

function exactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(record).sort();
  return (
    actual.length === keys.length && actual.every((key, index) => key === [...keys].sort()[index])
  );
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function sameIdentity(left: FileIdentity, right: FileIdentity): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

function canonicalPath(filename: string): string {
  const resolved = path.resolve(/* turbopackIgnore: true */ filename);
  const real = path.resolve(/* turbopackIgnore: true */ realpathSync.native(resolved));
  if (
    process.platform === "win32" ? real.toLowerCase() !== resolved.toLowerCase() : real !== resolved
  ) {
    throw new Error("Whisper artifact path is not canonical");
  }
  return resolved;
}

function assertProtectedStat(
  stat: Stats,
  options: { executable: boolean; maxSize?: number }
): void {
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    stat.size <= 0 ||
    (options.maxSize !== undefined && stat.size > options.maxSize)
  ) {
    throw new Error("Whisper artifact is not one protected regular file");
  }
  if (process.platform !== "win32") {
    if ((stat.mode & 0o222) !== 0 || (options.executable && (stat.mode & 0o111) === 0)) {
      throw new Error("Whisper artifact permissions are not protected");
    }
    if (process.env.NODE_ENV === "production" && stat.uid !== 0) {
      throw new Error("Production Whisper artifacts must be root-owned");
    }
  }
}

function readProtectedManifest(filename: string): RuntimeManifest {
  const resolved = path.resolve(/* turbopackIgnore: true */ filename);
  const before = lstatSync(resolved);
  assertProtectedStat(before, { executable: false, maxSize: MAX_MANIFEST_BYTES });
  canonicalPath(resolved);
  const descriptor = openSync(resolved, constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (!sameIdentity(before, opened)) throw new Error("Whisper manifest changed while opening");
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (!sameIdentity(opened, after)) throw new Error("Whisper manifest changed while reading");
    return validateRuntimeManifest(JSON.parse(bytes.toString("utf8")));
  } finally {
    closeSync(descriptor);
  }
}

function validateRuntimeManifest(value: unknown): RuntimeManifest {
  const record = asRecord(value);
  const source = asRecord(record?.source);
  const binary = asRecord(record?.binary);
  const model = asRecord(record?.model);
  const authority: WhisperArtifactAuthority = artifactConfiguration;
  const canonicalModel = typeof model?.name === "string" ? authority.models[model.name] : undefined;
  if (
    !record ||
    !source ||
    !binary ||
    !model ||
    !exactKeys(record, [
      "schemaVersion",
      "kind",
      "source",
      "platform",
      "architecture",
      "binary",
      "model",
    ]) ||
    !exactKeys(source, ["repository", "tag", "commit"]) ||
    !exactKeys(binary, ["kind", "sha256", "size"]) ||
    !exactKeys(model, ["name", "repository", "revision", "filename", "sha256", "size"]) ||
    record.schemaVersion !== 1 ||
    record.kind !== "terminalx.whisper-runtime-artifact" ||
    source.repository !== authority.source.repository ||
    source.tag !== authority.source.tag ||
    source.commit !== authority.source.commit ||
    !GIT_COMMIT.test(String(source.commit)) ||
    record.platform !== process.platform ||
    record.architecture !== process.arch ||
    binary.kind !== "whisper-cli" ||
    !SHA256.test(String(binary.sha256)) ||
    !Number.isSafeInteger(binary.size) ||
    Number(binary.size) <= 0 ||
    !canonicalModel ||
    model.repository !== authority.modelRepository.repository ||
    model.revision !== authority.modelRepository.revision ||
    model.filename !== canonicalModel.filename ||
    model.sha256 !== canonicalModel.sha256 ||
    model.size !== canonicalModel.size ||
    !SHA256.test(String(model.sha256)) ||
    !Number.isSafeInteger(model.size) ||
    Number(model.size) <= 0
  ) {
    throw new Error("Invalid Whisper runtime artifact manifest");
  }
  return value as RuntimeManifest;
}

function assertContainedByRoot(root: string, filename: string): string {
  const canonicalRoot = canonicalPath(root);
  const canonicalFilename = canonicalPath(filename);
  const relative = path.relative(canonicalRoot, canonicalFilename);
  if (
    !relative ||
    relative.startsWith(`..${path.sep}`) ||
    relative === ".." ||
    path.isAbsolute(relative)
  ) {
    throw new Error("Whisper artifact must be contained by its configured trust root");
  }
  if (process.env.NODE_ENV === "production") {
    if (process.platform === "win32" || process.geteuid?.() === 0) {
      throw new Error("Production Whisper verification requires a non-root POSIX server process");
    }
    let current = path.dirname(canonicalFilename);
    for (;;) {
      const stat = lstatSync(current);
      if (
        !stat.isDirectory() ||
        stat.isSymbolicLink() ||
        stat.uid !== 0 ||
        (stat.mode & 0o022) !== 0 ||
        canonicalPath(current) !== current
      ) {
        throw new Error("Production Whisper artifact directories must be root-owned and protected");
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  return canonicalFilename;
}

async function verifyProtectedArtifact(
  filename: string,
  expected: { readonly sha256: string; readonly size: number; readonly executable: boolean }
): Promise<void> {
  const resolved = path.resolve(/* turbopackIgnore: true */ filename);
  const before = lstatSync(resolved);
  assertProtectedStat(before, { executable: expected.executable });
  canonicalPath(resolved);
  if (before.size !== expected.size) throw new Error("Whisper artifact size mismatch");

  const cacheKey = `${resolved}\0${expected.sha256}\0${expected.size}`;
  const cached = verifiedArtifactCache.get(cacheKey);
  if (cached && sameIdentity(before, cached.identity)) return;

  const descriptor = await open(resolved, constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = await descriptor.stat();
    if (!sameIdentity(before, opened)) throw new Error("Whisper artifact changed while opening");
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
    if (!sameIdentity(opened, after) || position !== after.size) {
      throw new Error("Whisper artifact changed while hashing");
    }
    if (digest.digest("hex") !== expected.sha256) {
      throw new Error("Whisper artifact digest mismatch");
    }
    verifiedArtifactCache.set(cacheKey, { expected: expected.sha256, identity: after });
  } finally {
    await descriptor.close();
  }
}

export async function verifyWhisperRuntimeArtifacts(options: {
  readonly root: string;
  readonly binaryPath: string;
  readonly modelPath: string;
  readonly manifestPath: string;
  readonly modelName: string;
}): Promise<VerifiedWhisperRuntimeArtifacts> {
  const manifestPath = assertContainedByRoot(options.root, options.manifestPath);
  const binaryPath = assertContainedByRoot(options.root, options.binaryPath);
  const modelPath = assertContainedByRoot(options.root, options.modelPath);
  const manifest = readProtectedManifest(manifestPath);
  if (manifest.model.name !== options.modelName) {
    throw new Error("Configured Whisper model does not match its trusted manifest");
  }
  await Promise.all([
    verifyProtectedArtifact(binaryPath, { ...manifest.binary, executable: true }),
    verifyProtectedArtifact(modelPath, { ...manifest.model, executable: false }),
  ]);
  return Object.freeze({ binaryPath, modelPath, modelName: manifest.model.name });
}
