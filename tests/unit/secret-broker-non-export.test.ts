import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  assertClosedResponse,
  canonicalJson,
  RECEIPT_PAYLOAD_FIELDS,
  RESPONSE_SCHEMAS,
  SECRET_BROKER_METHODS,
  SECRET_BROKER_PROTOCOL_VERSION,
  type SecretBrokerMethod,
} from "../../packages/secret-broker/src/protocol";
import { runSecretBrokerConnection } from "../../packages/secret-broker/src/ndjson";

const RECEIPT = {
  payload: {
    schema: 1,
    kind: "terminalx.secret-broker-registration-receipt",
    brokerInstanceId: "i",
    brokerEpoch: 1,
    signingKeyId: "k",
    operationId: "o",
    handleId: "h",
    receiptId: "r",
    provider: "slack",
    brokerKind: "oauth-envelope",
    usage: "installation",
    expectationDigest: "d",
    hasReplacement: false,
    issuedAtMs: 1,
    expiresAtMs: 2,
  },
  signature: "s",
};

const VALID_RESPONSES: Readonly<Record<SecretBrokerMethod, unknown>> = {
  "registration.prepare": { receipt: RECEIPT },
  "rotation.prepare": { receipt: RECEIPT },
  "registration.finalize": { handleId: "h", status: "active" },
  "registration.abort": { receiptId: "r", status: "aborted" },
  "rotation.finalize": {
    handleId: "h",
    status: "active",
    replacedHandleId: "old",
    replacedStatus: "revoked",
  },
  "rotation.abort": { receiptId: "r", status: "aborted" },
  "handle.revoke": { handleId: "h", status: "revoked" },
  "handle.status": {
    handleId: "h",
    status: "active",
    brokerKind: "oauth-envelope",
    provider: "slack",
    usage: "installation",
    expiresAtMs: 2,
  },
  "broker.health": {
    brokerInstanceId: "i",
    brokerEpoch: 1,
    signingKeyId: "k",
    pendingRegistrations: 0,
  },
  "exchange.slack-oauth": {
    receipt: RECEIPT,
    installation: {
      provider: "slack",
      externalTenantId: "T1",
      externalAppId: "A1",
      externalBotUserId: "U1",
      grantedScopes: ["chat:write"],
    },
  },
  "exchange.telegram-bot-token": {
    receipt: RECEIPT,
    botIdentity: {
      provider: "telegram",
      externalTenantId: "998877",
      externalAppId: "998877",
      botId: "998877",
      username: "example_bot",
    },
    webhookAuthDigest: "d".repeat(64),
  },
  "webhook.verify-slack": { valid: true, withinReplayWindow: true },
};

const FORBIDDEN =
  /secret|token|password|private|plaintext|material|cipher|envelope|value|key(?!Id)/i;

describe("Secret Broker non-exporting protocol", () => {
  it("no response or receipt field name can carry secret material", () => {
    const allFields = new Set<string>(RECEIPT_PAYLOAD_FIELDS);
    for (const fields of Object.values(RESPONSE_SCHEMAS)) {
      for (const name of fields) allFields.add(name);
    }
    for (const name of allFields) {
      expect(name, `response field "${name}" looks secret-bearing`).not.toMatch(FORBIDDEN);
    }
  });

  it("accepts each method's exact closed response", () => {
    for (const method of SECRET_BROKER_METHODS) {
      expect(() => assertClosedResponse(method, VALID_RESPONSES[method])).not.toThrow();
    }
  });

  it("rejects any response carrying an unexpected (potentially secret) field", () => {
    for (const method of SECRET_BROKER_METHODS) {
      const leaking = { ...(VALID_RESPONSES[method] as object), secret: "leak" };
      expect(() => assertClosedResponse(method, leaking), method).toThrow();
    }
  });

  it("rejects a receipt whose payload gained an extra field", () => {
    const leaking = {
      receipt: { payload: { ...RECEIPT.payload, secret: "leak" }, signature: "s" },
    };
    expect(() => assertClosedResponse("registration.prepare", leaking)).toThrow();
  });

  it("a handler that tries to leak is turned into an error frame, never the secret", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const chunks: Buffer[] = [];
    output.on("data", (chunk: Buffer) => chunks.push(chunk));
    const controller = new AbortController();
    const done = runSecretBrokerConnection({
      input,
      output,
      signal: controller.signal,
      handler: async () => ({ handleId: "h", status: "active", secret: "LEAKED-SECRET" }),
    });
    input.write(
      `${canonicalJson({
        version: SECRET_BROKER_PROTOCOL_VERSION,
        sequence: 1,
        method: "registration.finalize",
        params: { handleId: "h", receiptId: "r" },
      })}\n`
    );
    input.end();
    await done;
    const text = Buffer.concat(chunks).toString("utf8");
    expect(text).not.toContain("LEAKED-SECRET");
    expect(text).toContain('"ok":false');
    expect(text).toContain('"code":"internal"');
  });
});
