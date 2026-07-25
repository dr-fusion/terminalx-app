import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  createFetchProxyNetworkClient,
  ProxyNetworkError,
  type ProxyOutboundRequest,
} from "../../packages/secret-broker/src/proxy/network-client";

const servers: http.Server[] = [];

afterEach(async () => {
  while (servers.length > 0) {
    const server = servers.pop()!;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

async function listen(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no address");
  return `http://127.0.0.1:${address.port}`;
}

function request(
  overrides: Partial<ProxyOutboundRequest> & { origin: string }
): ProxyOutboundRequest {
  return {
    method: "GET",
    origin: overrides.origin,
    path: overrides.path ?? "/x",
    query: overrides.query ?? {},
    headers: overrides.headers ?? {},
    body: overrides.body ?? null,
    maxResponseBytes: overrides.maxResponseBytes ?? 64 * 1024,
    timeoutMs: overrides.timeoutMs ?? 5000,
  };
}

describe("Credential Proxy fetch network client", () => {
  it("performs a loopback request and returns status + body", async () => {
    const origin = await listen((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    const client = createFetchProxyNetworkClient();
    const response = await client.send(request({ origin, path: "/api/x", query: { a: "1" } }));
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body.toString("utf8"))).toEqual({ ok: true, path: "/api/x?a=1" });
  });

  it("requires TLS for a non-loopback origin", async () => {
    const client = createFetchProxyNetworkClient();
    await expect(
      client.send(request({ origin: "http://api.telegram.org", path: "/botX/x" }))
    ).rejects.toMatchObject({ kind: "tls-required" });
  });

  it("never follows a redirect", async () => {
    const origin = await listen((_req, res) => {
      res.writeHead(302, { location: "https://evil.example/steal" });
      res.end();
    });
    const client = createFetchProxyNetworkClient();
    await expect(client.send(request({ origin }))).rejects.toMatchObject({ kind: "redirect" });
  });

  it("enforces the response size cap before buffering", async () => {
    const origin = await listen((_req, res) => {
      res.writeHead(200);
      res.end(Buffer.alloc(4096, 0x61));
    });
    const client = createFetchProxyNetworkClient();
    await expect(client.send(request({ origin, maxResponseBytes: 1024 }))).rejects.toMatchObject({
      kind: "response-too-large",
    });
  });

  it("classifies a timeout after dispatch as ambiguous (timeout-after-send)", async () => {
    const origin = await listen((_req, res) => {
      // Never respond within the timeout window.
      setTimeout(() => {
        res.writeHead(200);
        res.end("late");
      }, 2000).unref();
    });
    const client = createFetchProxyNetworkClient();
    await expect(client.send(request({ origin, timeoutMs: 150 }))).rejects.toMatchObject({
      kind: "timeout-after-send",
    });
  });

  it("classifies a connection failure as a retryable transport error", async () => {
    const client = createFetchProxyNetworkClient();
    // Nothing is listening on this loopback port.
    await expect(
      client.send(request({ origin: "http://127.0.0.1:1", timeoutMs: 1000 }))
    ).rejects.toBeInstanceOf(ProxyNetworkError);
  });
});
