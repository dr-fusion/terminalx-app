import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { types as nodeTypes } from "node:util";
import type { Socket } from "node:net";
import {
  assertPinnedRootExecutable,
  capturePinnedRootExecutable,
  type PinnedRootExecutable,
} from "./pinned-root-executable";
import { DaytonaSupervisorProtocolError } from "./supervisor";
import type {
  DaytonaSupervisorUnixPeerCredentials,
  DaytonaSupervisorUnixPeerCredentialVerifier,
} from "./unix-socket-transport";

const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 10_000;
const MAX_OUTPUT_BYTES = 256;

export interface CreatePinnedLinuxPeerCredentialVerifierOptions extends PinnedRootExecutable {
  readonly timeoutMs?: number;
}

/**
 * Invoke the tiny hash-pinned SO_PEERCRED helper with only the accepted socket
 * duplicated to fd 3. Node has no public getsockopt(SO_PEERCRED) API; accepting
 * a caller-supplied uid would silently downgrade this boundary.
 */
export function createPinnedLinuxPeerCredentialVerifier(
  unsafeOptions: CreatePinnedLinuxPeerCredentialVerifierOptions
): DaytonaSupervisorUnixPeerCredentialVerifier {
  if (
    typeof unsafeOptions !== "object" ||
    unsafeOptions === null ||
    nodeTypes.isProxy(unsafeOptions)
  ) {
    throw new TypeError();
  }
  const executable = capturePinnedRootExecutable(unsafeOptions);
  const timeoutMs = unsafeOptions.timeoutMs ?? 2_000;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < MIN_TIMEOUT_MS ||
    timeoutMs > MAX_TIMEOUT_MS
  ) {
    throw new TypeError();
  }
  return async (
    socket: Socket,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorUnixPeerCredentials> => {
    if (!(signal instanceof AbortSignal) || signal.aborted || socket.destroyed) {
      throw new DaytonaSupervisorProtocolError("unavailable");
    }
    assertPinnedRootExecutable(executable);
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn(executable.executableFile, [], {
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
      throw new DaytonaSupervisorProtocolError("not-ready");
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
    assertPinnedRootExecutable(executable);
    if (failed || signal.aborted || exit.code !== 0 || exit.signal !== null) {
      zero(chunks);
      throw new DaytonaSupervisorProtocolError("permission-denied");
    }
    const output = Buffer.concat(chunks, bytes);
    zero(chunks);
    try {
      const parsed = JSON.parse(output.toString("utf8"));
      return snapshotCredentials(parsed);
    } catch {
      throw new DaytonaSupervisorProtocolError("permission-denied");
    } finally {
      output.fill(0);
    }
  };
}

function snapshotCredentials(value: unknown): DaytonaSupervisorUnixPeerCredentials {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== 3 ||
    keys.some((key) => typeof key !== "string" || !["pid", "uid", "gid"].includes(key))
  ) {
    throw new TypeError();
  }
  const record = value as Record<string, unknown>;
  const pid = integerField(record, "pid", 1);
  const uid = integerField(record, "uid", 0);
  const gid = integerField(record, "gid", 0);
  return Object.freeze({ pid, uid, gid });
}

function integerField(record: Record<string, unknown>, name: string, minimum: number): number {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (
    !descriptor ||
    !descriptor.enumerable ||
    !("value" in descriptor) ||
    !Number.isSafeInteger(descriptor.value) ||
    descriptor.value < minimum
  ) {
    throw new TypeError();
  }
  return descriptor.value;
}

function zero(chunks: readonly Buffer[]): void {
  for (const chunk of chunks) chunk.fill(0);
}
