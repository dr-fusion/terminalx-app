#!/usr/local/bin/node

import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  fsyncSync,
  lstatSync,
  openSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { TextDecoder, types as nodeTypes } from "node:util";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import { readTrustedConfigurationFile } from "../../../src/lib/runtime/runtime-trusted-configuration-file";
import {
  snapshotDaytonaSupervisorBootstrapConfiguration,
  type DaytonaSupervisorBootstrapConfiguration,
} from "./daemon";
import { createDaytonaEffectiveIsolationVerifier } from "./effective-isolation";
import {
  DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
  DaytonaSupervisorSocketFrameDecoder,
  encodeDaytonaSupervisorSocketFrame,
  snapshotDaytonaSupervisorSocketInboundFrame,
  type DaytonaSupervisorSocketInboundFrame,
  type DaytonaSupervisorSocketOutboundFrame,
} from "./socket-framing";
import {
  DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
  DaytonaSupervisorProtocolError,
  type DaytonaSupervisorProtocolErrorCode,
} from "./supervisor";
import { createUnixSocketDaytonaSupervisorTransport } from "./unix-socket-transport";
import { writeOwnedBuffer } from "./owned-writable";

export const TERMINALX_ROOT_RUNTIME_DIRECTORY = "/run/terminalx-root" as const;
export const TERMINALX_ROOT_SUPERVISOR_SOCKET = "/run/terminalx-root/supervisor.sock" as const;
export const DAYTONA_RUNNER_ISOLATION_EVIDENCE_MAX_BYTES = 256 * 1024;
const MAX_EXTERNAL_FRAME_BYTES = 1024 * 1024 + 4;
const MAX_RELAY_STDIN_BYTES =
  4 + DAYTONA_RUNNER_ISOLATION_EVIDENCE_MAX_BYTES + MAX_EXTERNAL_FRAME_BYTES;
const ASSIGNMENT_BOOTSTRAP_FILE = "/run/terminalx-root/assignment/bootstrap.json" as const;
const LIVE_EVIDENCE_DIRECTORY = "/run/terminalx-root/live" as const;
const LIVE_EVIDENCE_FILE = "/run/terminalx-root/live/isolation-attestation.json" as const;
const PROVIDER_IDENTITY_DIGEST_DOMAIN = "terminalx/daytona-provider-identity/v1\0";

/**
 * Fixed Docker-exec target for the hardened runner relay endpoint. It exposes
 * no command, argument, path, environment, PTY, shell, filesystem or generic
 * exec surface. Running the file as the terminalx uid is explicitly denied;
 * it is not setuid and the root socket remains 0600.
 */
export async function runFixedDaytonaSupervisorRelay(): Promise<void> {
  if (
    typeof process.geteuid !== "function" ||
    process.geteuid() !== 0 ||
    process.argv.length !== 2
  ) {
    throw new DaytonaSupervisorProtocolError("permission-denied");
  }
  const input = await readRelayInput();
  installVerifiedRunnerIsolationEvidence(input.evidence, input.evidenceBytes, input.request);
  const request = input.request;
  const transport = createUnixSocketDaytonaSupervisorTransport({
    socketDirectory: TERMINALX_ROOT_RUNTIME_DIRECTORY,
    socketPath: TERMINALX_ROOT_SUPERVISOR_SOCKET,
    expectedOwnerUid: 0,
    connectTimeoutMs: 2_000,
    requestTimeoutMs: 30_000,
    connectAttempts: 1,
  });
  const controller = new AbortController();
  const abort = (): void => controller.abort();
  process.once("SIGINT", abort);
  process.once("SIGTERM", abort);
  try {
    if (request.method === "isolation.attest") {
      const result = await transport.attestIsolation(request.params as never, controller.signal);
      await writeFrame(success(request.requestId, result));
      return;
    }
    if (request.method === "command.execute") {
      const result = await transport.executeAuthenticated(
        request.params as never,
        controller.signal
      );
      await writeFrame(success(request.requestId, result));
      return;
    }
    if (request.method === "terminal.input") {
      await transport.terminalInput(request.params, controller.signal);
      await writeFrame(success(request.requestId, null));
      return;
    }
    if (request.method === "terminal.resize") {
      await transport.terminalResize(request.params, controller.signal);
      await writeFrame(success(request.requestId, null));
      return;
    }
    if (request.method === "terminal.interrupt") {
      await transport.terminalInterrupt(request.params, controller.signal);
      await writeFrame(success(request.requestId, null));
      return;
    }
    if (request.method === "terminal.destroy") {
      await transport.terminalDestroy(request.params, controller.signal);
      await writeFrame(success(request.requestId, null));
      return;
    }
    const stream =
      request.method === "terminal.open"
        ? transport.openTerminal(request.params, controller.signal)
        : transport.followSigned(request.params as never, controller.signal);
    for await (const item of stream) {
      await writeFrame(
        Object.freeze({
          protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
          version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
          type: "stream" as const,
          requestId: request.requestId,
          item: snapshotRuntimeSupervisorPortableData(item),
        })
      );
    }
    await writeFrame(
      Object.freeze({
        protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
        version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
        type: "end" as const,
        requestId: request.requestId,
      })
    );
  } catch (error) {
    const code: DaytonaSupervisorProtocolErrorCode =
      error instanceof DaytonaSupervisorProtocolError ? error.code : "internal";
    await writeFrame(failure(request.requestId, code));
  } finally {
    controller.abort();
    process.removeListener("SIGINT", abort);
    process.removeListener("SIGTERM", abort);
    await transport.close().catch(() => undefined);
  }
}

export interface FixedDaytonaSupervisorRelayInput {
  readonly evidence: unknown;
  readonly evidenceBytes: Buffer;
  readonly request: Extract<DaytonaSupervisorSocketInboundFrame, { readonly type: "request" }>;
}

async function readRelayInput(): Promise<FixedDaytonaSupervisorRelayInput> {
  const input = Buffer.alloc(MAX_RELAY_STDIN_BYTES + 1);
  let inputBytes = 0;
  try {
    for await (const unsafeChunk of process.stdin) {
      const chunk = Buffer.isBuffer(unsafeChunk) ? unsafeChunk : Buffer.from(unsafeChunk);
      try {
        if (inputBytes + chunk.byteLength > MAX_RELAY_STDIN_BYTES) {
          throw new DaytonaSupervisorProtocolError("invalid-request");
        }
        chunk.copy(input, inputBytes);
        inputBytes += chunk.byteLength;
      } finally {
        chunk.fill(0);
      }
    }
    return parseFixedDaytonaSupervisorRelayInput(input.subarray(0, inputBytes));
  } finally {
    input.fill(0);
  }
}

/** Strict pure parser for the runner-to-root relay stdin contract. */
export function parseFixedDaytonaSupervisorRelayInput(
  unsafeInput: Uint8Array
): FixedDaytonaSupervisorRelayInput {
  if (
    !(unsafeInput instanceof Uint8Array) ||
    nodeTypes.isProxy(unsafeInput) ||
    unsafeInput.byteLength < 6 ||
    unsafeInput.byteLength > MAX_RELAY_STDIN_BYTES
  ) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  const input = Buffer.from(unsafeInput);
  let evidenceBytes: Buffer | undefined;
  try {
    const evidenceLength = input.readUInt32BE(0);
    if (
      evidenceLength < 2 ||
      evidenceLength > DAYTONA_RUNNER_ISOLATION_EVIDENCE_MAX_BYTES ||
      4 + evidenceLength >= input.byteLength
    ) {
      throw new DaytonaSupervisorProtocolError("invalid-request");
    }
    evidenceBytes = Buffer.from(input.subarray(4, 4 + evidenceLength));
    let evidence: unknown;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(evidenceBytes);
      evidence = snapshotRuntimeSupervisorPortableData(JSON.parse(text));
      if (canonicalRuntimeJson(evidence) !== text) throw new TypeError();
    } catch {
      throw new DaytonaSupervisorProtocolError("invalid-request");
    }
    const frameBytes = input.subarray(4 + evidenceLength);
    if (frameBytes.byteLength > MAX_EXTERNAL_FRAME_BYTES) {
      throw new DaytonaSupervisorProtocolError("invalid-request");
    }
    const request = decodeSingleRequest(frameBytes);
    const result = Object.freeze({ evidence, evidenceBytes, request });
    evidenceBytes = undefined;
    return result;
  } finally {
    input.fill(0);
    evidenceBytes?.fill(0);
  }
}

function decodeSingleRequest(
  bytes: Buffer
): Extract<DaytonaSupervisorSocketInboundFrame, { readonly type: "request" }> {
  const decoder = new DaytonaSupervisorSocketFrameDecoder();
  const frames: DaytonaSupervisorSocketInboundFrame[] = [];
  for (const frame of decoder.push(bytes)) {
    frames.push(snapshotDaytonaSupervisorSocketInboundFrame(frame));
    if (frames.length > 1) throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  decoder.finish();
  const request = frames[0];
  if (!request || request.type !== "request") {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return request;
}

function installVerifiedRunnerIsolationEvidence(
  evidence: unknown,
  evidenceBytes: Buffer,
  request: Extract<DaytonaSupervisorSocketInboundFrame, { readonly type: "request" }>
): void {
  try {
    const configuration = readAssignmentBootstrap();
    if (providerSandboxIdFromRequest(request) !== configuration.assignment.providerSandboxId) {
      throw new DaytonaSupervisorProtocolError("permission-denied");
    }
    const plan = configuration.assignment.plan;
    const verifier = createDaytonaEffectiveIsolationVerifier(configuration.isolation);
    if (
      verifier(
        Object.freeze({
          attestation: evidence,
          plan,
          providerIdentityCommitment: digestText(
            PROVIDER_IDENTITY_DIGEST_DOMAIN,
            configuration.assignment.providerSandboxId
          ),
          artifactDigest: configuration.assignment.artifactDigest,
          supervisorArtifactDigest: configuration.assignment.supervisorArtifactDigest,
          observationIssuerKeyId: plan.observation.issuerKeyId,
          observationPublicKeyDigest: rawSha256(plan.observation.publicKeySpkiPem),
        })
      ) !== true
    ) {
      throw new DaytonaSupervisorProtocolError("not-ready");
    }
    writeAtomicLiveEvidence(evidenceBytes);
  } finally {
    evidenceBytes.fill(0);
  }
}

function readAssignmentBootstrap(): DaytonaSupervisorBootstrapConfiguration {
  const bytes = readTrustedConfigurationFile({
    trustedConfigurationRoot: TERMINALX_ROOT_RUNTIME_DIRECTORY,
    filePath: ASSIGNMENT_BOOTSTRAP_FILE,
    minimumBytes: 2,
    maximumBytes: 2 * 1024 * 1024,
  });
  try {
    return snapshotDaytonaSupervisorBootstrapConfiguration(JSON.parse(bytes.toString("utf8")));
  } finally {
    bytes.fill(0);
  }
}

function providerSandboxIdFromRequest(
  request: Extract<DaytonaSupervisorSocketInboundFrame, { readonly type: "request" }>
): string {
  const params = request.params;
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  const descriptor = Object.getOwnPropertyDescriptor(params, "providerSandboxId");
  if (!descriptor || !("value" in descriptor) || typeof descriptor.value !== "string") {
    throw new DaytonaSupervisorProtocolError("invalid-request");
  }
  return descriptor.value;
}

function writeAtomicLiveEvidence(bytes: Buffer): void {
  const directoryStat = lstatSync(LIVE_EVIDENCE_DIRECTORY);
  if (
    realpathSync.native(LIVE_EVIDENCE_DIRECTORY) !== LIVE_EVIDENCE_DIRECTORY ||
    directoryStat.isSymbolicLink() ||
    !directoryStat.isDirectory() ||
    directoryStat.uid !== 0 ||
    (directoryStat.mode & 0o777) !== 0o700
  ) {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
  const temporary = `${LIVE_EVIDENCE_DIRECTORY}/.isolation-${randomBytes(12).toString("hex")}`;
  let descriptor = -1;
  let committed = false;
  try {
    descriptor = openSync(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollowFlag(),
      0o600
    );
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = -1;
    chmodSync(temporary, 0o600);
    renameSync(temporary, LIVE_EVIDENCE_FILE);
    committed = true;
    const directoryDescriptor = openSync(
      LIVE_EVIDENCE_DIRECTORY,
      fsConstants.O_RDONLY | noFollowFlag()
    );
    try {
      fsyncSync(directoryDescriptor);
    } finally {
      closeSync(directoryDescriptor);
    }
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
    if (!committed) {
      try {
        unlinkSync(temporary);
      } catch {
        // The exact random temporary may not have been created.
      }
    }
  }
}

function digestText(domain: string, value: string): string {
  return createHash("sha256").update(domain, "utf8").update(value, "utf8").digest("hex");
}

function rawSha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function noFollowFlag(): number {
  return fsConstants.O_NOFOLLOW ?? 0;
}

function success(requestId: string, result: unknown): DaytonaSupervisorSocketOutboundFrame {
  return Object.freeze({
    protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
    version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
    type: "response",
    requestId,
    ok: true,
    result: snapshotRuntimeSupervisorPortableData(result),
  });
}

function failure(
  requestId: string,
  code: DaytonaSupervisorProtocolErrorCode
): DaytonaSupervisorSocketOutboundFrame {
  return Object.freeze({
    protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
    version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
    type: "response",
    requestId,
    ok: false,
    error: Object.freeze({ code, message: new DaytonaSupervisorProtocolError(code).message }),
  });
}

async function writeFrame(frame: DaytonaSupervisorSocketOutboundFrame): Promise<void> {
  // Canonicalize once before allocating the wire frame so accessors/proxies can
  // never run after privileged work completes.
  canonicalRuntimeJson(frame);
  const bytes = encodeDaytonaSupervisorSocketFrame(frame);
  await writeOwnedBuffer(process.stdout, bytes);
}

if (require.main === module) {
  runFixedDaytonaSupervisorRelay().catch(() => {
    process.stderr.write("TerminalX supervisor relay failed closed\n");
    process.exitCode = 77;
  });
}
