import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { canonicalJson } from "../../packages/secret-broker/src/protocol";
import {
  CREDENTIAL_PROXY_PROTOCOL_VERSION,
  type ProxyResult,
} from "../../packages/secret-broker/src/proxy/proxy-protocol";
import { runCredentialProxyConnection } from "../../packages/secret-broker/src/proxy/proxy-transport";

const VALID_RESULT: ProxyResult = {
  operation: "telegram.sendMessage",
  provider: "telegram",
  destinationHost: "api.telegram.org",
  resultClass: "ok",
  ambiguous: false,
  errorCode: null,
  requestBytes: 10,
  responseBytes: 20,
  handleGeneration: 1,
  installationRevision: 1,
  bindingRevision: null,
  startedAtMs: 1,
  completedAtMs: 2,
  accountingRowId: 1,
  projection: { messageId: 1, date: 2 },
};

function frame(method: string, params: unknown, sequence = 1): string {
  return `${canonicalJson({ version: CREDENTIAL_PROXY_PROTOCOL_VERSION, sequence, method, params })}\n`;
}

async function serve(
  input: string,
  handler: (request: { method: string; params: unknown }) => Promise<unknown>
): Promise<string> {
  const inputStream = new PassThrough();
  const outputStream = new PassThrough();
  const chunks: Buffer[] = [];
  outputStream.on("data", (chunk: Buffer) => chunks.push(chunk));
  const controller = new AbortController();
  const done = runCredentialProxyConnection({
    input: inputStream,
    output: outputStream,
    signal: controller.signal,
    handler,
  });
  inputStream.write(input);
  inputStream.end();
  await done;
  return Buffer.concat(chunks).toString("utf8");
}

describe("Credential Proxy transport", () => {
  it("serves a valid proxy.execute result frame", async () => {
    const text = await serve(frame("proxy.execute", {}), async () => VALID_RESULT);
    expect(text).toContain('"ok":true');
    expect(text).toContain('"messageId":1');
  });

  it("turns a leaking result into an error frame, never the leaked field", async () => {
    const text = await serve(frame("proxy.execute", {}), async () => ({
      ...VALID_RESULT,
      authorization: "Bearer LEAKED-TOKEN",
    }));
    expect(text).not.toContain("LEAKED-TOKEN");
    expect(text).toContain('"ok":false');
    expect(text).toContain('"code":"internal"');
  });

  it("rejects an unknown method", async () => {
    const text = await serve(frame("proxy.reveal", {}), async () => VALID_RESULT);
    expect(text).toContain('"ok":false');
    expect(text).toContain('"code":"invalid-request"');
  });

  it("rejects a non-monotonic sequence", async () => {
    const text = await serve(
      `${frame("proxy.execute", {}, 2)}${frame("proxy.execute", {}, 1)}`,
      async () => VALID_RESULT
    );
    expect(text).toContain('"code":"conflict"');
  });
});
