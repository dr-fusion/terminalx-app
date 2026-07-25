import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
  DaytonaSupervisorSocketFrameDecoder,
  encodeDaytonaSupervisorSocketFrame,
  type DaytonaSupervisorSocketRequestFrame,
} from "../../packages/daytona-supervisor/src/socket-framing";
import {
  DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
  DaytonaSupervisorProtocolError,
} from "../../packages/daytona-supervisor/src/supervisor";
import type {
  DaytonaSupervisorFollowRequest,
  DaytonaSupervisorIsolationRequest,
} from "../../src/lib/runtime/daytona-hosted-control-plane";
import type { DaytonaSupervisorPtyOpenRequest } from "../../src/lib/runtime/daytona-hosted-terminal-adapter";
import {
  DAYTONA_SUPERVISOR_RELAY_MEDIA_TYPE,
  createDaytonaSupervisorRelayTransport,
} from "../../src/lib/runtime/daytona-supervisor-relay-transport";

const PROVIDER_ID = "123e4567-e89b-42d3-a456-426614174000";
const TEST_SPKI_SHA256 = "7bec64d026f8fb3f11d8063c657c3553415dc0258da2679e25fbab6c1203b279";
const TEST_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIDGjCCAgKgAwIBAgIUa2NQpxak8vjX8TYzaxjwYSMn0zswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MDcyNDIyMDAzMFoXDTM2MDcy
MTIyMDAzMFowFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA1ZiuR1sEjaOEm7g64L2Z8HWIoeSglBYZ1B71KxN+7mJ4
im0h/Wgx+AsWwaWXEF6OgWxoprMadUBe58NmEVy6sw5gAfqTFDMRA8mjRkd8Hbv4
NcCRtzLWFSnQKdg9Sv6nYsRLojSiHAdVmADvUzrj0KPsEzn8bSO+GhqVf/q34SUs
/gBsTbvWIOvU4tKq5pTcgSjVWvuqqMrTnQfDbHJ+IlBMyB4dbsaow+HJJ6bQWNeE
89tRVbM7BLRpC6Xji/ctCTR/IFpbsQKZuWN1d1csW7C8NzdPM6H9SwvMVimtTgd+
pNw0Gioe8WokFZ0pNF87jTsBoNccRe3DL2f5Gc7LnQIDAQABo2QwYjAdBgNVHQ4E
FgQU0MYS8qUKViGkRbCfKKxocfbFXUAwHwYDVR0jBBgwFoAU0MYS8qUKViGkRbCf
KKxocfbFXUAwDwYDVR0TAQH/BAUwAwEB/zAPBgNVHREECDAGhwR/AAABMA0GCSqG
SIb3DQEBCwUAA4IBAQCHGpWJ/jiNxzW8FH9eFQ1WOdp0G0LSp3Bgh0dXIldhlpNY
KrstITUA1yCXomHiFXZHjD8TuW53SXihzGhMCQUrUBIl6Z9vwjfuU9k9o2Wt+gCk
UOFTDtNMznFV+Av6JL6gcxKmEtaIDDLc05+UhUtj02159B0cBiEBHzHNW3nVq6Z9
x8xkDuk1pA4+BfdN5RZELrhzT5Nk/7OMZZsciSIIdAfDjGR1j1YMkTSZ13q/Tpwy
wb5nZDtN7F/phh1sJeupwM4cJJ0kCB1Lfjw/6L+nVbaO5ylBdkl8C5XDh2T3whNa
NXsQwgJ/+tXlCJ/QTy5dUuZnGHkoxvkYBhZiy9AO
-----END CERTIFICATE-----
`;
const TEST_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDVmK5HWwSNo4Sb
uDrgvZnwdYih5KCUFhnUHvUrE37uYniKbSH9aDH4CxbBpZcQXo6BbGimsxp1QF7n
w2YRXLqzDmAB+pMUMxEDyaNGR3wdu/g1wJG3MtYVKdAp2D1K/qdixEuiNKIcB1WY
AO9TOuPQo+wTOfxtI74aGpV/+rfhJSz+AGxNu9Yg69Ti0qrmlNyBKNVa+6qoytOd
B8Nscn4iUEzIHh1uxqjD4cknptBY14Tz21FVszsEtGkLpeOL9y0JNH8gWluxApm5
Y3V3VyxbsLw3N08zof1LC8xWKa1OB36k3DQaKh7xaiQVnSk0XzuNOwGg1xxF7cMv
Z/kZzsudAgMBAAECggEAAmQcPccxMo0KeMpXa/HpoeHGf8E6aYJqKP5CR7o/8t4n
KTv7ddd/ZbO+vioKBNlAy9u2raNEk7GbMe1DvJmhcmiFe1ZpR+rbNJlJuO0LGaxx
3clJYTDSMGoSRh4WjHPlt6BaooGSRf+M6MUdr9j4gEj/s5FJTU4+3+fEOQ5JlfKj
NeTekYgFLdSbJLpsGQvRkvCQA7PD8IPqdTswOLiHjaAzaGP3euCTBbx/g0QoWR4S
2hDnMLVdMrEeoBbWWjt28nhRqIwmFKXhhu6BZtcA6RDaJffZ8A6cbD1whJ6D4ze0
0o4kHNGjYRYre/xeB98kDo1GqZddPYGP1rhkFs5XGQKBgQD0EVqUnyYK64Rnfu48
+DcCIYV/xBf+LUaw8lEDe8+hASrAnvPpoA7iVMPeIEDUpdVPr19HAj8vUZEOVgl4
mEPnmKGRII9aMEmukZA50hGsdUlVpRPXARai1cUQe8GQcwC7y4rp39LUrR7ZzbXb
0XppPqSeyuGDpuyjZ+Y0Jv+elQKBgQDgCfXe6KTXYvVP05IZpwRa46WZXe7WyoZ2
HEYOjWFUyHH743BdwTnK17JJwL7MY5U9vSZuH89O5pV+hQ/80OOREUH6XZJQ0D8x
G2MuxOnGeqck6l0d/PvMYfU2pGBbI38sD8aED2kkqETtHcMQeFeysHKLXBmnjgES
V+jaMcoe6QKBgF8M/xzQWi14iWkRCtEdzbZ7vZUDlmB724L/68MSjcrjPHYlsVIz
7ngAkQNJxlXKe6d74fwyiM7x0i8mHKwliJSCYbG2X329PoTI1cVe5VknmDbNgkuC
dgFWhVelCr4pu4hnfaMVcvM2tMQYFBIWo7inF89rraXq9U+yH/oBkh19AoGAbeX0
6geM9OriEuphvJulE0CgNv9Q7aQjGUT9SJ4ppIE/CKSkthjW1J3CI1OdRH2E8+gZ
NeP8uWN66bk0AnwlZT/l8X59C49bsCcTHBoT4vy/iOg+DTvP+I4Ez20Kpypec6q5
YoZ8uTKhvP7gdO/TdSAA0EO5geuysuDUpFPQJiECgYBA1bJNgJeBPgy3r91KI49F
K4AObnNizJO2dJ4/QDEFHOkAEJa+IRB0Vy87khXLL7DQb0+TS+xRV9c3QIRrpHqr
xfSZLjonjk9eP7AyjsO5pTC2fe4SgVuyVmoS0IN03dLotbs268/CQGKnWBl6wFHs
LE/3E+sDT4JTJleqDOojGA==
-----END PRIVATE KEY-----
`;

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
          server.closeAllConnections();
        })
    )
  );
});

describe("Daytona supervisor relay HTTPS transport", () => {
  it("pins TLS and sends one exact framed unary request to the fixed route", async () => {
    let observed:
      | {
          readonly method: string | undefined;
          readonly url: string | undefined;
          readonly authorization: string | undefined;
          readonly accept: string | undefined;
          readonly contentType: string | undefined;
          readonly request: DaytonaSupervisorSocketRequestFrame;
        }
      | undefined;
    const origin = await listen(async (request, response) => {
      const body = await readRequest(request);
      const frame = decodeRequest(body);
      observed = {
        method: request.method,
        url: request.url,
        authorization: request.headers.authorization,
        accept: request.headers.accept,
        contentType: request.headers["content-type"],
        request: frame,
      };
      respondWithFrames(response, [
        encodeDaytonaSupervisorSocketFrame({
          protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
          version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
          type: "response",
          requestId: frame.requestId,
          ok: true,
          result: { attested: true },
        }),
      ]);
    });
    const credential = new TextEncoder().encode("runner-relay-credential");
    const transport = createTransport(origin, credential);
    expect(credential.every((byte) => byte === 0)).toBe(true);
    const input = isolationRequest();

    await expect(transport.attestIsolation(input, new AbortController().signal)).resolves.toEqual({
      attested: true,
    });
    expect(observed).toMatchObject({
      method: "POST",
      url: `/sandboxes/${PROVIDER_ID}/terminalx-supervisor-relay`,
      authorization: "Bearer runner-relay-credential",
      accept: DAYTONA_SUPERVISOR_RELAY_MEDIA_TYPE,
      contentType: DAYTONA_SUPERVISOR_RELAY_MEDIA_TYPE,
      request: {
        protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
        version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
        type: "request",
        method: "isolation.attest",
        params: input,
      },
    });

    await transport.close();
    await expect(
      transport.attestIsolation(input, new AbortController().signal)
    ).rejects.toMatchObject({ code: "unavailable" });
  });

  it("streams ordered follow frames and requires one terminal end frame", async () => {
    let requestCount = 0;
    const origin = await listen(async (request, response) => {
      const frame = decodeRequest(await readRequest(request));
      requestCount += 1;
      const frames = [
        encodeDaytonaSupervisorSocketFrame({
          protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
          version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
          type: "stream",
          requestId: frame.requestId,
          item: { sequence: 1 },
        }),
        encodeDaytonaSupervisorSocketFrame({
          protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
          version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
          type: "stream",
          requestId: frame.requestId,
          item: { sequence: 2 },
        }),
      ];
      if (requestCount === 1) {
        frames.push(
          encodeDaytonaSupervisorSocketFrame({
            protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
            version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
            type: "end",
            requestId: frame.requestId,
          })
        );
      }
      respondWithFrames(response, frames);
    });
    const transport = createTransport(origin);

    const items: unknown[] = [];
    for await (const item of transport.followSigned(
      followRequest(),
      new AbortController().signal
    )) {
      items.push(item);
    }
    expect(items).toEqual([{ sequence: 1 }, { sequence: 2 }]);

    const truncated: unknown[] = [];
    await expect(
      (async () => {
        for await (const item of transport.followSigned(
          followRequest(),
          new AbortController().signal
        )) {
          truncated.push(item);
        }
      })()
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(truncated).toEqual([{ sequence: 1 }, { sequence: 2 }]);
    await transport.close();
  });

  it("preserves explicit supervisor failures but rejects malformed or incorrectly typed relay data", async () => {
    let requestCount = 0;
    const origin = await listen(async (request, response) => {
      const frame = decodeRequest(await readRequest(request));
      requestCount += 1;
      if (requestCount === 1) {
        const error = new DaytonaSupervisorProtocolError("permission-denied");
        respondWithFrames(response, [
          encodeDaytonaSupervisorSocketFrame({
            protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
            version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
            type: "response",
            requestId: frame.requestId,
            ok: false,
            error: { code: error.code, message: error.message },
          }),
        ]);
        return;
      }
      if (requestCount === 2) {
        response.writeHead(200, { "content-type": DAYTONA_SUPERVISOR_RELAY_MEDIA_TYPE });
        response.end(nonCanonicalFrame(frame.requestId));
        return;
      }
      response.writeHead(200, { "content-type": "application/octet-stream" });
      response.end();
    });
    const transport = createTransport(origin);

    await expect(
      transport.attestIsolation(isolationRequest(), new AbortController().signal)
    ).rejects.toMatchObject({ code: "permission-denied" });
    await expect(
      transport.attestIsolation(isolationRequest(), new AbortController().signal)
    ).rejects.toMatchObject({ code: "unavailable" });
    await expect(
      transport.attestIsolation(isolationRequest(), new AbortController().signal)
    ).rejects.toMatchObject({ code: "unavailable" });
    await transport.close();
  });

  it("carries one fenced PTY through ready, mutations, ordered output, exit, and destroy", async () => {
    let openResponse: import("node:http").ServerResponse | undefined;
    let openRequestId = "";
    const methods: string[] = [];
    const origin = await listen(async (request, response) => {
      const frame = decodeRequest(await readRequest(request));
      methods.push(frame.method);
      if (frame.method === "terminal.open") {
        openResponse = response;
        openRequestId = frame.requestId;
        response.writeHead(200, {
          "content-type": DAYTONA_SUPERVISOR_RELAY_MEDIA_TYPE,
          "cache-control": "no-store",
        });
        response.write(
          encodeDaytonaSupervisorSocketFrame({
            protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
            version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
            type: "stream",
            requestId: frame.requestId,
            item: { kind: "ready", ...ptyFence() },
          })
        );
        return;
      }
      if (frame.method === "terminal.input") {
        expect(frame.params).toEqual({
          ...ptyFence(),
          inputSeq: 1,
          bytesBase64: Buffer.from("whoami\n").toString("base64url"),
        });
      }
      if (frame.method === "terminal.resize") {
        expect(frame.params).toEqual({ ...ptyFence(), resizeSeq: 1, cols: 132, rows: 41 });
      }
      if (frame.method === "terminal.interrupt") {
        expect(frame.params).toEqual({ ...ptyFence(), interruptSeq: 1 });
      }
      respondWithFrames(response, [
        encodeDaytonaSupervisorSocketFrame({
          protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
          version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
          type: "response",
          requestId: frame.requestId,
          ok: true,
          result: null,
        }),
      ]);
      if (frame.method === "terminal.interrupt") {
        const stream = openResponse;
        if (!stream) throw new Error("missing terminal stream");
        for (const item of [
          {
            kind: "output" as const,
            terminalId: ptyFence().terminalId,
            outputSeq: 1,
            bytesBase64: Buffer.from("terminalx\r\n").toString("base64url"),
          },
          { kind: "exit" as const, terminalId: ptyFence().terminalId },
        ]) {
          stream.write(
            encodeDaytonaSupervisorSocketFrame({
              protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
              version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
              type: "stream",
              requestId: openRequestId,
              item,
            })
          );
        }
        stream.end(
          encodeDaytonaSupervisorSocketFrame({
            protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
            version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
            type: "end",
            requestId: openRequestId,
          })
        );
      }
    });
    const transport = createTransport(origin);
    const connection = await transport.open(ptyOpenRequest(), new AbortController().signal);
    const outputs: string[] = [];
    connection.onData((frame) => outputs.push(Buffer.from(frame.bytes).toString("utf8")));
    const exited = new Promise<void>((resolve) => {
      connection.onExit((frame) => {
        expect(frame).toEqual({ terminalId: ptyFence().terminalId });
        resolve();
      });
    });
    const input = new TextEncoder().encode("whoami\n");
    await connection.input(
      { ...ptyFence(), inputSeq: 1, bytes: input },
      new AbortController().signal
    );
    expect(new TextDecoder().decode(input)).toBe("whoami\n");
    await connection.resize(
      { ...ptyFence(), resizeSeq: 1, cols: 132, rows: 41 },
      new AbortController().signal
    );
    await connection.interrupt({ ...ptyFence(), interruptSeq: 1 }, new AbortController().signal);
    await exited;
    expect(outputs).toEqual(["terminalx\r\n"]);
    await connection.destroy(ptyFence(), new AbortController().signal);
    expect(methods).toEqual([
      "terminal.open",
      "terminal.input",
      "terminal.resize",
      "terminal.interrupt",
      "terminal.destroy",
    ]);
    await transport.close();
  });

  it("fails closed on the wrong TLS pin and zeroes rejected configuration credentials", async () => {
    const origin = await listen(async (request, response) => {
      await readRequest(request);
      response.writeHead(500).end();
    });
    const transport = createDaytonaSupervisorRelayTransport({
      runnerOrigin: origin,
      runnerCaPem: TEST_CERTIFICATE,
      runnerTlsSpkiSha256: "0".repeat(64),
      runnerCredential: new TextEncoder().encode("runner-credential"),
      requestTimeoutMs: 2_000,
    });
    await expect(
      transport.attestIsolation(isolationRequest(), new AbortController().signal)
    ).rejects.toMatchObject({ code: "unavailable" });
    await transport.close();

    const rejectedCredential = new TextEncoder().encode("must-be-zeroed");
    expect(() =>
      createDaytonaSupervisorRelayTransport({
        runnerOrigin: origin,
        runnerCaPem: "not-a-ca",
        runnerTlsSpkiSha256: TEST_SPKI_SHA256,
        runnerCredential: rejectedCredential,
      })
    ).toThrow(TypeError);
    expect(rejectedCredential.every((byte) => byte === 0)).toBe(true);

    const accessorCredential = new TextEncoder().encode("accessor-secret");
    const accessor = Object.defineProperties(
      {},
      {
        runnerOrigin: { value: origin, enumerable: true },
        runnerCaPem: { get: () => TEST_CERTIFICATE, enumerable: true },
        runnerTlsSpkiSha256: { value: TEST_SPKI_SHA256, enumerable: true },
        runnerCredential: { value: accessorCredential, enumerable: true },
      }
    );
    expect(() => createDaytonaSupervisorRelayTransport(accessor as never)).toThrow(TypeError);
    expect(accessorCredential.every((byte) => byte === 0)).toBe(true);
  });
});

function createTransport(origin: string, credential?: Uint8Array) {
  return createDaytonaSupervisorRelayTransport({
    runnerOrigin: origin,
    runnerCaPem: TEST_CERTIFICATE,
    runnerTlsSpkiSha256: TEST_SPKI_SHA256,
    runnerCredential: credential ?? new TextEncoder().encode("runner-relay-credential"),
    connectTimeoutMs: 1_000,
    requestTimeoutMs: 2_000,
  });
}

function isolationRequest(): DaytonaSupervisorIsolationRequest {
  return Object.freeze({
    providerSandboxId: PROVIDER_ID,
    plan: Object.freeze({ marker: "plan" }),
    artifactDigest: "a".repeat(64),
    sandboxUser: "terminalx",
    trust: Object.freeze({ marker: "trust" }),
  }) as unknown as DaytonaSupervisorIsolationRequest;
}

function followRequest(): DaytonaSupervisorFollowRequest {
  return Object.freeze({
    providerSandboxId: PROVIDER_ID,
    expectedRevision: 1,
    checkpoint: null,
    trust: Object.freeze({ marker: "trust" }),
  }) as unknown as DaytonaSupervisorFollowRequest;
}

function ptyFence() {
  return Object.freeze({
    providerSandboxId: PROVIDER_ID,
    expectedProviderRevision: 7,
    binding: Object.freeze({
      teamId: "team-1",
      projectId: "project-1",
      sessionId: "session-1",
      runtimeAssignmentId: "assignment-1",
      runtimeAssignmentGeneration: 2,
      sandboxId: "sandbox-1",
      sandboxGeneration: 3,
      runtimePrincipalId: "principal-1",
    }),
    planDigest: "b".repeat(64),
    terminalId: "223e4567-e89b-42d3-a456-426614174001",
  });
}

function ptyOpenRequest(): DaytonaSupervisorPtyOpenRequest {
  return Object.freeze({ ...ptyFence(), cols: 120, rows: 36 });
}

async function listen(handler: Parameters<typeof createServer>[1]): Promise<string> {
  const server = createServer(
    { key: TEST_PRIVATE_KEY, cert: TEST_CERTIFICATE },
    (request, response) => {
      Promise.resolve(handler?.(request, response)).catch(() => {
        if (!response.headersSent) response.writeHead(500);
        response.end();
      });
    }
  );
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address() as AddressInfo;
  return `https://127.0.0.1:${address.port}`;
}

async function readRequest(request: import("node:http").IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const unsafeChunk of request) {
    chunks.push(Buffer.from(unsafeChunk));
  }
  return Buffer.concat(chunks);
}

function decodeRequest(body: Buffer): DaytonaSupervisorSocketRequestFrame {
  const decoder = new DaytonaSupervisorSocketFrameDecoder();
  const frames = decoder.push(body);
  decoder.finish();
  expect(frames).toHaveLength(1);
  const frame = frames[0];
  expect(frame?.type).toBe("request");
  return frame as DaytonaSupervisorSocketRequestFrame;
}

function respondWithFrames(
  response: import("node:http").ServerResponse,
  frames: readonly Buffer[]
): void {
  response.writeHead(200, { "content-type": DAYTONA_SUPERVISOR_RELAY_MEDIA_TYPE });
  response.end(Buffer.concat(frames));
}

function nonCanonicalFrame(requestId: string): Buffer {
  const payload = Buffer.from(
    `{"protocol":"${DAYTONA_SUPERVISOR_SOCKET_PROTOCOL}", "version":${DAYTONA_SUPERVISOR_PROTOCOL_VERSION},"type":"response","requestId":"${requestId}","ok":true,"result":{}}`,
    "utf8"
  );
  const frame = Buffer.allocUnsafe(4 + payload.byteLength);
  frame.writeUInt32BE(payload.byteLength, 0);
  payload.copy(frame, 4);
  payload.fill(0);
  return frame;
}
