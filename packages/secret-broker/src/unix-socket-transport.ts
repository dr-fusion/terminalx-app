import { chmodSync, existsSync, lstatSync, realpathSync, unlinkSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { dirname, isAbsolute, normalize } from "node:path";
import { runSecretBrokerConnection, type SecretBrokerRequestHandler } from "./ndjson";
import { assertAllowedPeer, type SecretBrokerPeerCredentialVerifier } from "./peer-credentials";
import { SecretBrokerProtocolError } from "./protocol";

export interface SecretBrokerDenialEvent {
  readonly reason: "peer-credentials" | "connection-error";
  readonly code: string;
}

export interface StartSecretBrokerUnixServerOptions {
  readonly socketPath: string;
  readonly expectedOwnerUid?: number;
  readonly expectedParentPid?: number;
  readonly verifyPeerCredentials: SecretBrokerPeerCredentialVerifier;
  readonly handler: SecretBrokerRequestHandler;
  readonly maxConnections?: number;
  /** Structured, secret-free audit sink (defaults to stderr in the daemon). */
  readonly onDenial?: (event: SecretBrokerDenialEvent) => void;
}

export interface SecretBrokerUnixServer {
  readonly socketPath: string;
  close(): Promise<void>;
}

/**
 * Listen on a Unix domain socket inside the 0700 broker root. Each accepted
 * connection is admitted only after SO_PEERCRED confirms the same effective uid
 * (and, when configured, the expected parent pid). Everything fails closed.
 */
export async function startSecretBrokerUnixServer(
  options: StartSecretBrokerUnixServerOptions
): Promise<SecretBrokerUnixServer> {
  const socketPath = canonicalAbsolutePath(options.socketPath);
  const expectedOwnerUid =
    options.expectedOwnerUid ?? (typeof process.geteuid === "function" ? process.geteuid() : 0);
  if (!Number.isSafeInteger(expectedOwnerUid) || expectedOwnerUid < 0) throw new TypeError();
  if (typeof process.geteuid === "function" && process.geteuid() !== expectedOwnerUid) {
    throw new SecretBrokerProtocolError("permission-denied");
  }
  if (typeof options.verifyPeerCredentials !== "function") throw new TypeError();
  assertPrivateParentDirectory(socketPath, expectedOwnerUid);
  removeStaleSocket(socketPath, expectedOwnerUid);

  const maxConnections = options.maxConnections ?? 64;
  const active = new Set<Socket>();
  const server: Server = createServer({ pauseOnConnect: true }, (socket) => {
    void admit(socket, options, expectedOwnerUid, active);
  });
  server.maxConnections = maxConnections;

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  chmodSync(socketPath, 0o600);

  return Object.freeze({
    socketPath,
    async close(): Promise<void> {
      for (const socket of active) socket.destroy();
      active.clear();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      try {
        unlinkSync(socketPath);
      } catch {
        // Already removed.
      }
    },
  });
}

async function admit(
  socket: Socket,
  options: StartSecretBrokerUnixServerOptions,
  expectedOwnerUid: number,
  active: Set<Socket>
): Promise<void> {
  active.add(socket);
  socket.once("close", () => active.delete(socket));
  const controller = new AbortController();
  socket.once("error", () => controller.abort());
  socket.once("close", () => controller.abort());
  try {
    const credentials = await options.verifyPeerCredentials(socket, controller.signal);
    assertAllowedPeer(credentials, {
      uid: expectedOwnerUid,
      parentPid: options.expectedParentPid,
    });
  } catch (error) {
    options.onDenial?.({
      reason: "peer-credentials",
      code: error instanceof SecretBrokerProtocolError ? error.code : "internal",
    });
    socket.destroy();
    active.delete(socket);
    return;
  }
  socket.resume();
  try {
    await runSecretBrokerConnection({
      input: socket,
      output: socket,
      handler: options.handler,
      signal: controller.signal,
    });
  } catch (error) {
    options.onDenial?.({
      reason: "connection-error",
      code: error instanceof SecretBrokerProtocolError ? error.code : "internal",
    });
  } finally {
    socket.destroy();
    active.delete(socket);
  }
}

function assertPrivateParentDirectory(socketPath: string, expectedOwnerUid: number): void {
  const parent = dirname(socketPath);
  try {
    if (realpathSync.native(parent) !== parent) throw new TypeError();
    const stat = lstatSync(parent);
    if (
      stat.isSymbolicLink() ||
      !stat.isDirectory() ||
      stat.uid !== expectedOwnerUid ||
      (stat.mode & 0o077) !== 0
    ) {
      throw new TypeError();
    }
  } catch {
    throw new SecretBrokerProtocolError("not-ready");
  }
}

function removeStaleSocket(socketPath: string, expectedOwnerUid: number): void {
  if (!existsSync(socketPath)) return;
  const stat = lstatSync(socketPath);
  if (stat.isSymbolicLink() || !stat.isSocket() || stat.uid !== expectedOwnerUid) {
    throw new SecretBrokerProtocolError("not-ready");
  }
  unlinkSync(socketPath);
}

function canonicalAbsolutePath(value: unknown): string {
  if (typeof value !== "string" || !isAbsolute(value) || normalize(value) !== value) {
    throw new SecretBrokerProtocolError("not-ready");
  }
  return value;
}
