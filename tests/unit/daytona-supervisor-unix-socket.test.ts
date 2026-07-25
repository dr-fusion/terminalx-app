import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
  DaytonaSupervisorSocketFrameDecoder,
  encodeDaytonaSupervisorSocketFrame,
} from "../../packages/daytona-supervisor/src/socket-framing";
import {
  createDaytonaSupervisorUnixSocketServer,
  createUnixSocketDaytonaSupervisorTransport,
} from "../../packages/daytona-supervisor/src/unix-socket-transport";
import { DAYTONA_SUPERVISOR_PROTOCOL_VERSION } from "../../packages/daytona-supervisor/src/supervisor";
import type { DaytonaSupervisorPtyService } from "../../packages/daytona-supervisor/src/pty-registry";
import type { PinnedDaytonaSupervisorTransport } from "@/lib/runtime/daytona-hosted-control-plane";

const uid = process.getuid?.() ?? 0;
const gid = process.getgid?.() ?? 0;

describe("Daytona root Unix socket transport", () => {
  it("multiplexes commands while a follow stream is pending", async () => {
    const boundary = temporaryBoundary();
    let release!: () => void;
    const pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    const command = vi.fn(async () => ({
      commandId: "command-1",
      commandDigest: "a".repeat(64),
      receipt: {} as never,
      observation: {},
      attestations: [],
    }));
    const supervisor = fixtureSupervisor({
      command,
      follow: async function* () {
        await pending;
        yield { cursor: "1", signed: true };
      },
    });
    const server = createServer(boundary, supervisor);
    await server.listen();
    const client = createClient(boundary);
    try {
      const followed: unknown[] = [];
      const following = (async () => {
        for await (const value of client.followSigned({} as never, new AbortController().signal)) {
          followed.push(value);
        }
      })();
      await Promise.resolve();
      const outcome = await client.executeAuthenticated({} as never, new AbortController().signal);
      expect(outcome).toMatchObject({ commandId: "command-1" });
      expect(command).toHaveBeenCalledOnce();
      release();
      await following;
      expect(followed).toEqual([{ cursor: "1", signed: true }]);
    } finally {
      release();
      await client.close();
      await server.close();
      boundary.remove();
    }
  });

  it("rejects an unauthenticated peer before dispatch", async () => {
    const boundary = temporaryBoundary();
    const attest = vi.fn(async () => ({ attested: true }));
    const supervisor = fixtureSupervisor({ attest });
    const server = createDaytonaSupervisorUnixSocketServer({
      supervisor,
      terminal: fixtureTerminal(),
      socketDirectory: boundary.directory,
      socketPath: boundary.socket,
      expectedOwnerUid: uid,
      expectedPeerUid: uid,
      verifyPeerCredentials: async () => ({ pid: process.pid, uid: uid + 1, gid }),
      requestTimeoutMs: 1_000,
    });
    await server.listen();
    const client = createClient(boundary);
    try {
      await expect(
        client.attestIsolation({} as never, new AbortController().signal)
      ).rejects.toMatchObject({ code: "unavailable" });
      expect(attest).not.toHaveBeenCalled();
    } finally {
      await client.close();
      await server.close();
      boundary.remove();
    }
  });

  it("fails closed on socket directory permission drift", async () => {
    const boundary = temporaryBoundary();
    const supervisor = fixtureSupervisor();
    chmodSync(boundary.directory, 0o755);
    const server = createServer(boundary, supervisor);
    await expect(server.listen()).rejects.toMatchObject({ code: "not-ready" });
    await server.close();
    boundary.remove();
  });

  it("cancels timed-out work and does not accept a late result", async () => {
    const boundary = temporaryBoundary();
    let observedAbort = false;
    const supervisor = fixtureSupervisor({
      attest: async (_request, signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener(
            "abort",
            () => {
              observedAbort = true;
              reject(new Error("late"));
            },
            { once: true }
          );
        }),
    });
    const server = createServer(boundary, supervisor, { requestTimeoutMs: 150 });
    await server.listen();
    const client = createClient(boundary, { requestTimeoutMs: 500 });
    try {
      await expect(
        client.attestIsolation({} as never, new AbortController().signal)
      ).rejects.toMatchObject({ code: "unavailable" });
      expect(observedAbort).toBe(true);
    } finally {
      await client.close();
      await server.close();
      boundary.remove();
    }
  });

  it("reconnects only for a later request after a connection loss", async () => {
    const boundary = temporaryBoundary();
    let admissions = 0;
    const supervisor = fixtureSupervisor();
    const server = createDaytonaSupervisorUnixSocketServer({
      supervisor,
      terminal: fixtureTerminal(),
      socketDirectory: boundary.directory,
      socketPath: boundary.socket,
      expectedOwnerUid: uid,
      expectedPeerUid: uid,
      verifyPeerCredentials: async () => ({
        pid: process.pid,
        uid: ++admissions === 1 ? uid + 1 : uid,
        gid,
      }),
      requestTimeoutMs: 1_000,
    });
    await server.listen();
    const client = createClient(boundary);
    try {
      await expect(
        client.attestIsolation({} as never, new AbortController().signal)
      ).rejects.toMatchObject({ code: "unavailable" });
      // The first failure is not implicitly replayed. A distinct caller retry
      // establishes a fresh, independently authenticated connection.
      await expect(
        client.attestIsolation({} as never, new AbortController().signal)
      ).resolves.toEqual({ attested: true });
      expect(admissions).toBe(2);
    } finally {
      await client.close();
      await server.close();
      boundary.remove();
    }
  });
});

describe("Daytona supervisor socket framing", () => {
  it("decodes fragmented length-prefixed frames and poisons malformed input", () => {
    const frame = {
      protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
      version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
      type: "cancel" as const,
      requestId: "connection:1",
    };
    const bytes = encodeDaytonaSupervisorSocketFrame(frame);
    const decoder = new DaytonaSupervisorSocketFrameDecoder();
    expect(decoder.push(bytes.subarray(0, 2))).toEqual([]);
    expect(decoder.push(bytes.subarray(2))).toEqual([frame]);
    bytes.fill(0);

    const malformed = new DaytonaSupervisorSocketFrameDecoder(1024);
    const header = Buffer.alloc(4);
    header.writeUInt32BE(1025, 0);
    expect(() => malformed.push(header)).toThrowError(
      expect.objectContaining({
        code: "invalid-request",
      })
    );
    expect(() => malformed.push(Buffer.from("x"))).toThrowError();
  });
});

function createServer(
  boundary: ReturnType<typeof temporaryBoundary>,
  supervisor: PinnedDaytonaSupervisorTransport,
  overrides: { requestTimeoutMs?: number } = {}
) {
  return createDaytonaSupervisorUnixSocketServer({
    supervisor,
    terminal: fixtureTerminal(),
    socketDirectory: boundary.directory,
    socketPath: boundary.socket,
    expectedOwnerUid: uid,
    expectedPeerUid: uid,
    expectedPeerGid: gid,
    verifyPeerCredentials: async () => ({ pid: process.pid, uid, gid }),
    requestTimeoutMs: overrides.requestTimeoutMs ?? 2_000,
  });
}

function fixtureTerminal(): DaytonaSupervisorPtyService {
  const unavailable = async (): Promise<void> => {
    throw new Error("unused");
  };
  return {
    open: async function* () {
      throw new Error("unused");
    },
    input: unavailable,
    resize: unavailable,
    interrupt: unavailable,
    destroy: unavailable,
    close: async () => undefined,
  };
}

function createClient(
  boundary: ReturnType<typeof temporaryBoundary>,
  overrides: { requestTimeoutMs?: number } = {}
) {
  return createUnixSocketDaytonaSupervisorTransport({
    socketDirectory: boundary.directory,
    socketPath: boundary.socket,
    expectedOwnerUid: uid,
    connectTimeoutMs: 500,
    requestTimeoutMs: overrides.requestTimeoutMs ?? 2_000,
    connectAttempts: 1,
  });
}

function fixtureSupervisor(
  overrides: {
    attest?: PinnedDaytonaSupervisorTransport["attestIsolation"];
    command?: PinnedDaytonaSupervisorTransport["executeAuthenticated"];
    follow?: PinnedDaytonaSupervisorTransport["followSigned"];
  } = {}
): PinnedDaytonaSupervisorTransport {
  return {
    attestIsolation: overrides.attest ?? (async () => ({ attested: true })),
    executeAuthenticated:
      overrides.command ??
      (async () => ({
        commandId: "command-1",
        commandDigest: "a".repeat(64),
        receipt: {} as never,
        observation: {},
        attestations: [],
      })),
    followSigned:
      overrides.follow ??
      async function* () {
        yield { cursor: "1" };
      },
    close: async () => undefined,
  };
}

function temporaryBoundary() {
  const directory = mkdtempSync(join(tmpdir(), "terminalx-supervisor-socket-"));
  chmodSync(directory, 0o700);
  return {
    directory,
    socket: join(directory, "supervisor.sock"),
    remove() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}
