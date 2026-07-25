import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { openAtRest, sealAtRest } from "../../packages/secret-broker/src/at-rest";
import {
  createOauthEnvelopeAdapter,
  openOauthEnvelopeForTest,
} from "../../packages/secret-broker/src/adapters/oauth-envelope";
import {
  createOnePasswordConnectAdapter,
  createOnePasswordConnectHttpClient,
} from "../../packages/secret-broker/src/adapters/onepassword-connect";
import { openSecretBrokerStateStore } from "../../packages/secret-broker/src/state-store";
import { SecretBrokerProtocolError } from "../../packages/secret-broker/src/protocol";

const temporaryDirectories: string[] = [];
function temporaryDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secret-broker-adapters-"));
  temporaryDirectories.push(dir);
  return dir;
}
afterEach(() => {
  while (temporaryDirectories.length > 0) {
    fs.rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

describe("at-rest AES-256-GCM envelope", () => {
  it("round-trips and detects tampering", () => {
    const key = randomBytes(32);
    const sealed = sealAtRest(Buffer.from("super-secret-oauth-token"), key);
    expect(openAtRest(sealed, key).toString("utf8")).toBe("super-secret-oauth-token");
    const tampered = Buffer.from(sealed);
    tampered[tampered.length - 1] ^= 0xff;
    expect(() => openAtRest(tampered, key)).toThrow();
    const wrongKey = randomBytes(32);
    expect(() => openAtRest(sealed, wrongKey)).toThrow();
  });

  it("requires a 32-byte key and never emits plaintext", () => {
    expect(() => sealAtRest(Buffer.from("x"), randomBytes(16))).toThrow();
    const key = randomBytes(32);
    const sealed = sealAtRest(Buffer.from("plaintext-secret"), key);
    expect(sealed.includes(Buffer.from("plaintext-secret"))).toBe(false);
  });
});

describe("oauth-envelope adapter", () => {
  it("seals material, zeroes the input, and round-trips under the broker key", async () => {
    const key = randomBytes(32);
    const adapter = createOauthEnvelopeAdapter(key);
    const input = Buffer.from("oauth-refresh-token");
    const prepared = await adapter.prepare(input);
    expect(input.every((byte) => byte === 0)).toBe(true);
    expect(prepared.material.includes(Buffer.from("oauth-refresh-token"))).toBe(false);
    expect(openOauthEnvelopeForTest(prepared.material, key).toString("utf8")).toBe(
      "oauth-refresh-token"
    );
  });

  it("stores only ciphertext in the broker database file", async () => {
    const dir = temporaryDir();
    const databasePath = path.join(dir, "broker.sqlite");
    const key = randomBytes(32);
    const adapter = createOauthEnvelopeAdapter(key);
    const sealed = await adapter.prepare(Buffer.from("PLAINTEXT-CANARY-VALUE"));
    const s = openSecretBrokerStateStore({ databasePath });
    s.prepare({
      operationId: "op_1",
      handleId: "hnd_1",
      receiptId: "rcp_1",
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "installation",
      expectationDigest: "a".repeat(64),
      replacesHandleId: null,
      issuedAtMs: 1000,
      expiresAtMs: 301_000,
      secretMaterial: sealed.material,
    });
    s.close();
    for (const suffix of ["", "-wal"]) {
      const file = `${databasePath}${suffix}`;
      if (!fs.existsSync(file)) continue;
      expect(fs.readFileSync(file).includes(Buffer.from("PLAINTEXT-CANARY-VALUE"))).toBe(false);
    }
  });
});

describe("onepassword-connect adapter", () => {
  const ref = Buffer.from(JSON.stringify({ schema: 1, vaultId: "v1", itemId: "i1" }));

  it("stores only the opaque reference when the item resolves", async () => {
    const adapter = createOnePasswordConnectAdapter({ client: { resolves: async () => true } });
    const prepared = await adapter.prepare(Buffer.from(ref));
    const parsed = JSON.parse(prepared.material.toString("utf8"));
    expect(parsed).toEqual({ schema: 1, vaultId: "v1", itemId: "i1" });
  });

  it("fails closed with invalid-request when the reference does not resolve", async () => {
    const adapter = createOnePasswordConnectAdapter({ client: { resolves: async () => false } });
    await expect(adapter.prepare(Buffer.from(ref))).rejects.toMatchObject({
      code: "invalid-request",
    });
  });

  it("fails closed with a retryable unavailable error on transport fault", async () => {
    const adapter = createOnePasswordConnectAdapter({
      client: {
        resolves: async () => {
          throw new Error("ECONNREFUSED");
        },
      },
    });
    await expect(adapter.prepare(Buffer.from(ref))).rejects.toMatchObject({ code: "unavailable" });
  });

  it("rejects malformed references", async () => {
    const adapter = createOnePasswordConnectAdapter({ client: { resolves: async () => true } });
    await expect(adapter.prepare(Buffer.from("not json"))).rejects.toBeInstanceOf(
      SecretBrokerProtocolError
    );
  });

  it("real HTTP client checks existence and discards the body", async () => {
    const requests: string[] = [];
    const fakeFetch = (async (url: URL) => {
      requests.push(url.pathname);
      return new Response(JSON.stringify({ fields: [{ value: "SECRET" }] }), { status: 200 });
    }) as unknown as typeof fetch;
    const client = createOnePasswordConnectHttpClient({
      connectHost: "https://connect.internal",
      token: "connect-token",
      fetchImpl: fakeFetch,
    });
    const controller = new AbortController();
    expect(await client.resolves({ vaultId: "v1", itemId: "i1" }, controller.signal)).toBe(true);
    expect(requests[0]).toBe("/v1/vaults/v1/items/i1");

    const missing = createOnePasswordConnectHttpClient({
      connectHost: "https://connect.internal",
      token: "connect-token",
      fetchImpl: (async () => new Response("", { status: 404 })) as unknown as typeof fetch,
    });
    expect(await missing.resolves({ vaultId: "v1", itemId: "x" }, controller.signal)).toBe(false);
  });
});
