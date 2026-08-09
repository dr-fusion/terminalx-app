import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  DAYTONA_ASSIGNMENT_BOOTSTRAP_REQUEST_MEDIA_TYPE,
  DAYTONA_ASSIGNMENT_BOOTSTRAP_RESPONSE_MEDIA_TYPE,
} from "../../packages/daytona-supervisor/src/assignment-bootstrap";
import {
  createDaytonaAssignmentBootstrapTransport,
  type DaytonaAssignmentBootstrapTransportError,
} from "../../src/lib/runtime/daytona-assignment-bootstrap-transport";
import { canonicalRuntimeJson } from "../../src/lib/runtime/runtime-command-canonical";

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

describe("Daytona assignment bootstrap HTTPS transport", () => {
  it("pins TLS, sends the exact private route, and zeroes credential and envelope ownership", async () => {
    let observed:
      | {
          readonly method: string | undefined;
          readonly url: string | undefined;
          readonly authorization: string | undefined;
          readonly accept: string | undefined;
          readonly contentType: string | undefined;
          readonly body: Buffer;
        }
      | undefined;
    const origin = await listen(async (request, response) => {
      const body = await readRequest(request);
      observed = {
        method: request.method,
        url: request.url,
        authorization: request.headers.authorization,
        accept: request.headers.accept,
        contentType: request.headers["content-type"],
        body,
      };
      response.writeHead(200, {
        "content-type": DAYTONA_ASSIGNMENT_BOOTSTRAP_RESPONSE_MEDIA_TYPE,
      });
      response.end(canonicalRuntimeJson({ kind: "installed" }));
    });
    const credential = new TextEncoder().encode("runner-bootstrap-credential");
    const transport = createDaytonaAssignmentBootstrapTransport({
      runnerOrigin: origin,
      runnerCaPem: TEST_CERTIFICATE,
      runnerTlsSpkiSha256: TEST_SPKI_SHA256,
      runnerCredential: credential,
      connectTimeoutMs: 1_000,
      requestTimeoutMs: 2_000,
    });
    expect(credential.every((byte) => byte === 0)).toBe(true);
    const envelope = Buffer.from([0, 1, 2, 3, 4, 5]);
    const expectedEnvelope = Buffer.from(envelope);

    await expect(
      transport.install(PROVIDER_ID, envelope, new AbortController().signal)
    ).resolves.toEqual({ kind: "installed" });
    expect(envelope.every((byte) => byte === 0)).toBe(true);
    expect(observed).toEqual({
      method: "POST",
      url: `/sandboxes/${PROVIDER_ID}/terminalx-assignment-bootstrap`,
      authorization: "Bearer runner-bootstrap-credential",
      accept: DAYTONA_ASSIGNMENT_BOOTSTRAP_RESPONSE_MEDIA_TYPE,
      contentType: DAYTONA_ASSIGNMENT_BOOTSTRAP_REQUEST_MEDIA_TYPE,
      body: expectedEnvelope,
    });

    await transport.close();
    const afterClose = Buffer.from([9]);
    await expect(
      transport.install(PROVIDER_ID, afterClose, new AbortController().signal)
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(afterClose[0]).toBe(0);
  });

  it("maps definitive status and rejects noncanonical or incorrectly typed responses", async () => {
    let requestNumber = 0;
    const origin = await listen(async (request, response) => {
      await readRequest(request);
      requestNumber += 1;
      if (requestNumber === 1) {
        response.writeHead(409).end();
        return;
      }
      response.writeHead(200, {
        "content-type":
          requestNumber === 3
            ? "application/json"
            : DAYTONA_ASSIGNMENT_BOOTSTRAP_RESPONSE_MEDIA_TYPE,
      });
      response.end(`${canonicalRuntimeJson({ kind: "installed" })}\n`);
    });
    const transport = createTransport(origin);

    await expectInstallError(transport, "conflict");
    await expectInstallError(transport, "unavailable");
    await expectInstallError(transport, "unavailable");
    await transport.close();
  });

  it("fails closed on the wrong TLS key pin and zeroes rejected configuration secrets", async () => {
    const origin = await listen(async (request, response) => {
      await readRequest(request);
      response.writeHead(500).end();
    });
    const transport = createDaytonaAssignmentBootstrapTransport({
      runnerOrigin: origin,
      runnerCaPem: TEST_CERTIFICATE,
      runnerTlsSpkiSha256: "0".repeat(64),
      runnerCredential: new TextEncoder().encode("runner-credential"),
      requestTimeoutMs: 2_000,
    });
    const envelope = Buffer.from([1, 2, 3]);
    await expect(
      transport.install(PROVIDER_ID, envelope, new AbortController().signal)
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(envelope.every((byte) => byte === 0)).toBe(true);
    await transport.close();

    const rejectedCredential = new TextEncoder().encode("must-be-zeroed");
    expect(() =>
      createDaytonaAssignmentBootstrapTransport({
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
    expect(() => createDaytonaAssignmentBootstrapTransport(accessor as never)).toThrow(TypeError);
    expect(accessorCredential.every((byte) => byte === 0)).toBe(true);
  });
});

function createTransport(origin: string) {
  return createDaytonaAssignmentBootstrapTransport({
    runnerOrigin: origin,
    runnerCaPem: TEST_CERTIFICATE,
    runnerTlsSpkiSha256: TEST_SPKI_SHA256,
    runnerCredential: new TextEncoder().encode("runner-credential"),
    requestTimeoutMs: 2_000,
  });
}

async function expectInstallError(
  transport: ReturnType<typeof createDaytonaAssignmentBootstrapTransport>,
  code: DaytonaAssignmentBootstrapTransportError["code"]
): Promise<void> {
  const envelope = Buffer.from([1, 2, 3]);
  await expect(
    transport.install(PROVIDER_ID, envelope, new AbortController().signal)
  ).rejects.toMatchObject({ code });
  expect(envelope.every((byte) => byte === 0)).toBe(true);
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
    chunks.push(Buffer.isBuffer(unsafeChunk) ? Buffer.from(unsafeChunk) : Buffer.from(unsafeChunk));
  }
  return Buffer.concat(chunks);
}
