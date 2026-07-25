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
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { types as nodeTypes } from "node:util";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import {
  DaytonaSupervisorProtocolError,
  type DaytonaSupervisorEffectExecutionRequest,
  type DaytonaSupervisorEffectExecutionResult,
  type DaytonaSupervisorEffectExecutor,
} from "./supervisor";

const SHA256 = /^[0-9a-f]{64}$/;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 10 * 60_000;
const MIN_INPUT_BYTES = 1024;
const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const MIN_OUTPUT_BYTES = 1024;
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024;

export interface CreatePinnedDaytonaEffectExecutorOptions {
  /** Root-owned, non-writable directory containing the pinned executor. */
  readonly executableRoot: string;
  /** Absolute executable path strictly below `executableRoot`. */
  readonly executableFile: string;
  readonly executableSha256: string;
  /** Provider-bound signed manifest claims digest for this assignment only. */
  readonly expectedEffectEnforcerSetDigest: string;
  readonly expectedOwnerUid: number;
  readonly timeoutMs: number;
  readonly maximumInputBytes?: number;
  readonly maximumOutputBytes?: number;
}

/**
 * Invoke a separately pinned effect enforcer without a shell or inherited
 * secrets. TerminalX does not ship a permissive fallback enforcer.
 */
export function createPinnedDaytonaEffectExecutor(
  unsafeOptions: CreatePinnedDaytonaEffectExecutorOptions
): DaytonaSupervisorEffectExecutor {
  const options = captureOptions(unsafeOptions);
  return Object.freeze({
    async execute(
      request: DaytonaSupervisorEffectExecutionRequest,
      signal: AbortSignal
    ): Promise<DaytonaSupervisorEffectExecutionResult> {
      assertNotAborted(signal);
      if (
        !sameDigest(
          request.requiredEffectEnforcerSetDigest,
          options.expectedEffectEnforcerSetDigest
        )
      ) {
        throw new DaytonaSupervisorProtocolError("conflict");
      }
      assertPinnedExecutable(options);
      let input: Buffer;
      try {
        input = Buffer.from(`${canonicalRuntimeJson(request)}\n`, "utf8");
      } catch {
        throw new DaytonaSupervisorProtocolError("invalid-request");
      }
      if (input.byteLength > options.maximumInputBytes) {
        input.fill(0);
        throw new DaytonaSupervisorProtocolError("invalid-request");
      }
      return executeProcess(options, input, signal);
    },
  });
}

async function executeProcess(
  options: CapturedOptions,
  input: Buffer,
  signal: AbortSignal
): Promise<DaytonaSupervisorEffectExecutionResult> {
  let child: ChildProcessWithoutNullStreams;
  try {
    child = spawn(options.executableFile, [], {
      cwd: "/",
      env: Object.freeze({
        PATH: "/usr/sbin:/usr/bin:/sbin:/bin",
        LANG: "C",
        LC_ALL: "C",
        NODE_ENV: "production",
      }),
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
  } catch {
    input.fill(0);
    throw new DaytonaSupervisorProtocolError("unavailable");
  }

  const outputChunks: Buffer[] = [];
  let outputBytes = 0;
  let failed = false;
  const fail = (): void => {
    failed = true;
    child.kill("SIGKILL");
  };
  const collect = (chunk: Buffer | string): void => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    outputBytes += bytes.byteLength;
    if (outputBytes > options.maximumOutputBytes) {
      fail();
      return;
    }
    outputChunks.push(Buffer.from(bytes));
  };
  child.stdout.on("data", collect);
  // stderr is intentionally discarded and never enters protocol errors/logs.
  child.stderr.resume();
  child.stdin.on("error", fail);
  child.stdin.end(input, () => input.fill(0));

  const abort = (): void => fail();
  signal.addEventListener("abort", abort, { once: true });
  const timeout = setTimeout(fail, options.timeoutMs);
  timeout.unref();
  const exit = await new Promise<Readonly<{ code: number | null; signal: NodeJS.Signals | null }>>(
    (resolve) => {
      child.once("error", fail);
      child.once("close", (code, exitSignal) => resolve({ code, signal: exitSignal }));
    }
  );
  clearTimeout(timeout);
  signal.removeEventListener("abort", abort);
  input.fill(0);
  try {
    assertPinnedExecutable(options);
  } catch (error) {
    zeroChunks(outputChunks);
    throw error;
  }
  if (failed || signal.aborted || exit.code !== 0 || exit.signal !== null) {
    zeroChunks(outputChunks);
    throw new DaytonaSupervisorProtocolError("unavailable");
  }

  try {
    const output = Buffer.concat(outputChunks, outputBytes);
    let parsed: unknown;
    try {
      parsed = snapshotRuntimeSupervisorPortableData(JSON.parse(output.toString("utf8")));
    } finally {
      output.fill(0);
      zeroChunks(outputChunks);
    }
    const record = exactRecord(parsed, ["receipt", "attestations"]);
    const attestations = field(record, "attestations");
    if (!Array.isArray(attestations) || attestations.length > 64) throw new TypeError();
    return Object.freeze({
      receipt: field(record, "receipt"),
      attestations: Object.freeze(attestations),
    });
  } catch {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
}

interface CapturedOptions {
  readonly executableRoot: string;
  readonly executableFile: string;
  readonly executableSha256: string;
  readonly expectedEffectEnforcerSetDigest: string;
  readonly expectedOwnerUid: number;
  readonly timeoutMs: number;
  readonly maximumInputBytes: number;
  readonly maximumOutputBytes: number;
}

function captureOptions(value: CreatePinnedDaytonaEffectExecutorOptions): CapturedOptions {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value))
    throw new TypeError();
  if (
    typeof value.executableRoot !== "string" ||
    !isAbsolute(value.executableRoot) ||
    normalize(value.executableRoot) !== value.executableRoot ||
    typeof value.executableFile !== "string" ||
    !isAbsolute(value.executableFile) ||
    normalize(value.executableFile) !== value.executableFile
  ) {
    throw new TypeError();
  }
  if (
    typeof value.executableSha256 !== "string" ||
    !SHA256.test(value.executableSha256) ||
    typeof value.expectedEffectEnforcerSetDigest !== "string" ||
    !SHA256.test(value.expectedEffectEnforcerSetDigest) ||
    !Number.isSafeInteger(value.expectedOwnerUid) ||
    value.expectedOwnerUid < 0 ||
    !Number.isSafeInteger(value.timeoutMs) ||
    value.timeoutMs < MIN_TIMEOUT_MS ||
    value.timeoutMs > MAX_TIMEOUT_MS
  ) {
    throw new TypeError();
  }
  const maximumInputBytes = value.maximumInputBytes ?? 1024 * 1024;
  if (
    !Number.isSafeInteger(maximumInputBytes) ||
    maximumInputBytes < MIN_INPUT_BYTES ||
    maximumInputBytes > MAX_INPUT_BYTES
  ) {
    throw new TypeError();
  }
  const maximumOutputBytes = value.maximumOutputBytes ?? 1024 * 1024;
  if (
    !Number.isSafeInteger(maximumOutputBytes) ||
    maximumOutputBytes < MIN_OUTPUT_BYTES ||
    maximumOutputBytes > MAX_OUTPUT_BYTES
  ) {
    throw new TypeError();
  }
  const options = Object.freeze({
    executableRoot: value.executableRoot,
    executableFile: value.executableFile,
    executableSha256: value.executableSha256,
    expectedEffectEnforcerSetDigest: value.expectedEffectEnforcerSetDigest,
    expectedOwnerUid: value.expectedOwnerUid,
    timeoutMs: value.timeoutMs,
    maximumInputBytes,
    maximumOutputBytes,
  });
  assertPinnedExecutable(options);
  return options;
}

function assertPinnedExecutable(options: CapturedOptions): void {
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

function assertProtectedExecutablePath(options: CapturedOptions): void {
  if (realpathSync.native(options.executableRoot) !== options.executableRoot) {
    throw new TypeError();
  }
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

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new TypeError();
  }
  const keys = Reflect.ownKeys(value);
  if (
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of names) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function assertNotAborted(signal: AbortSignal): void {
  try {
    AbortSignal.prototype.throwIfAborted.call(signal);
  } catch {
    throw new DaytonaSupervisorProtocolError("unavailable");
  }
}

function zeroChunks(chunks: readonly Buffer[]): void {
  for (const chunk of chunks) chunk.fill(0);
}

function sameDigest(left: string, right: string): boolean {
  return (
    SHA256.test(left) &&
    SHA256.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"))
  );
}

function noFollowFlag(): number {
  return fsConstants.O_NOFOLLOW ?? 0;
}
