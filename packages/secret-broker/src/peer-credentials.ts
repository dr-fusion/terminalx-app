import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, timingSafeEqual } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, normalize } from "node:path";
import type { Socket } from "node:net";
import { SecretBrokerProtocolError } from "./protocol";

export interface SecretBrokerPeerCredentials {
  readonly pid: number;
  readonly uid: number;
  readonly gid: number;
}

/**
 * Obtain SO_PEERCRED from an accepted connection. Node has no public
 * getsockopt(SO_PEERCRED) API, so production supplies a hash-pinned helper; a
 * test may inject a fake. The verifier must never trust a caller-supplied uid.
 */
export type SecretBrokerPeerCredentialVerifier = (
  socket: Socket,
  signal: AbortSignal
) => Promise<SecretBrokerPeerCredentials>;

const SHA256 = /^[0-9a-f]{64}$/;
const MAX_OUTPUT_BYTES = 256;
const MAX_EXECUTABLE_BYTES = 4 * 1024 * 1024;

export interface CreatePinnedPeerCredentialVerifierOptions {
  readonly executableFile: string;
  readonly executableSha256: string;
  readonly expectedOwnerUid?: number;
  readonly timeoutMs?: number;
}

/** Spawn the pinned SO_PEERCRED helper with the accepted socket on fd 3. */
export function createPinnedPeerCredentialVerifier(
  options: CreatePinnedPeerCredentialVerifierOptions
): SecretBrokerPeerCredentialVerifier {
  const executableFile = canonicalAbsolutePath(options.executableFile);
  if (typeof options.executableSha256 !== "string" || !SHA256.test(options.executableSha256)) {
    throw new TypeError();
  }
  const executableSha256 = options.executableSha256;
  const expectedOwnerUid =
    options.expectedOwnerUid ?? (typeof process.geteuid === "function" ? process.geteuid() : 0);
  const timeoutMs = options.timeoutMs ?? 2000;
  if (
    !Number.isSafeInteger(expectedOwnerUid) ||
    expectedOwnerUid < 0 ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 100 ||
    timeoutMs > 10_000
  ) {
    throw new TypeError();
  }
  const measure = (): void =>
    assertPinnedExecutable(executableFile, executableSha256, expectedOwnerUid);
  measure();

  return async (socket, signal) => {
    if (!(signal instanceof AbortSignal) || signal.aborted || socket.destroyed) {
      throw new SecretBrokerProtocolError("unavailable");
    }
    measure();
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn(executableFile, [], {
        cwd: "/",
        env: Object.freeze({
          PATH: "/usr/sbin:/usr/bin:/sbin:/bin",
          LANG: "C",
          LC_ALL: "C",
          NODE_ENV: "production",
        }),
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe", socket],
      }) as ChildProcessWithoutNullStreams;
    } catch {
      throw new SecretBrokerProtocolError("not-ready");
    }
    child.stderr.resume();
    const chunks: Buffer[] = [];
    let bytes = 0;
    let failed = false;
    const fail = (): void => {
      failed = true;
      child.kill("SIGKILL");
    };
    child.stdout.on("data", (chunk: Buffer | string) => {
      const copy = Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk, "utf8");
      bytes += copy.byteLength;
      if (bytes > MAX_OUTPUT_BYTES) {
        copy.fill(0);
        fail();
      } else {
        chunks.push(copy);
      }
    });
    const abort = (): void => fail();
    signal.addEventListener("abort", abort, { once: true });
    const timeout = setTimeout(fail, timeoutMs);
    timeout.unref();
    const exit = await new Promise<
      Readonly<{ code: number | null; signal: NodeJS.Signals | null }>
    >((resolve) => {
      child.once("error", fail);
      child.once("close", (code, exitSignal) => resolve({ code, signal: exitSignal }));
    });
    clearTimeout(timeout);
    signal.removeEventListener("abort", abort);
    measure();
    if (failed || signal.aborted || exit.code !== 0 || exit.signal !== null) {
      zero(chunks);
      throw new SecretBrokerProtocolError("permission-denied");
    }
    const output = Buffer.concat(chunks, bytes);
    zero(chunks);
    try {
      return snapshotCredentials(JSON.parse(output.toString("utf8")));
    } catch {
      throw new SecretBrokerProtocolError("permission-denied");
    } finally {
      output.fill(0);
    }
  };
}

/**
 * Restrict accepted peers to the same effective uid as the broker and, when a
 * parent pid is expected, to that process. Fail closed on any mismatch.
 */
export function assertAllowedPeer(
  credentials: SecretBrokerPeerCredentials,
  expected: Readonly<{ uid: number; parentPid?: number }>
): void {
  if (credentials.uid !== expected.uid) {
    throw new SecretBrokerProtocolError("permission-denied");
  }
  if (expected.parentPid !== undefined && credentials.pid !== expected.parentPid) {
    throw new SecretBrokerProtocolError("permission-denied");
  }
}

function snapshotCredentials(value: unknown): SecretBrokerPeerCredentials {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError();
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 3 || keys.some((key) => !["pid", "uid", "gid"].includes(key as string))) {
    throw new TypeError();
  }
  const record = value as Record<string, unknown>;
  return Object.freeze({
    pid: integerField(record, "pid", 1),
    uid: integerField(record, "uid", 0),
    gid: integerField(record, "gid", 0),
  });
}

function integerField(record: Record<string, unknown>, name: string, minimum: number): number {
  const value = record[name];
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw new TypeError();
  return value as number;
}

function assertPinnedExecutable(
  executableFile: string,
  executableSha256: string,
  expectedOwnerUid: number
): void {
  let descriptor = -1;
  try {
    if (realpathSync.native(executableFile) !== executableFile) throw new TypeError();
    descriptor = openSync(executableFile, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const stat = fstatSync(descriptor);
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.uid !== expectedOwnerUid ||
      (stat.mode & 0o022) !== 0 ||
      stat.size < 1 ||
      stat.size > MAX_EXECUTABLE_BYTES
    ) {
      throw new TypeError();
    }
    const bytes = readFileSync(descriptor);
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (!timingSafeEqual(Buffer.from(digest, "hex"), Buffer.from(executableSha256, "hex"))) {
      throw new TypeError();
    }
  } catch {
    throw new SecretBrokerProtocolError("permission-denied");
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function canonicalAbsolutePath(value: unknown): string {
  if (typeof value !== "string" || !isAbsolute(value) || normalize(value) !== value) {
    throw new TypeError();
  }
  return value;
}

function zero(chunks: readonly Buffer[]): void {
  for (const chunk of chunks) chunk.fill(0);
}
