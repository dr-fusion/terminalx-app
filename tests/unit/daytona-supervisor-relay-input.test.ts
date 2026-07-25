import { describe, expect, it } from "vitest";
import { parseFixedDaytonaSupervisorRelayInput } from "../../packages/daytona-supervisor/src/relay";
import {
  DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
  DaytonaSupervisorSocketFrameDecoder,
  encodeDaytonaSupervisorSocketFrame,
} from "../../packages/daytona-supervisor/src/socket-framing";
import { DAYTONA_SUPERVISOR_PROTOCOL_VERSION } from "../../packages/daytona-supervisor/src/supervisor";
import { canonicalRuntimeJson } from "../../src/lib/runtime/runtime-command-canonical";

const PROVIDER_ID = "123e4567-e89b-42d3-a456-426614174000";

describe("fixed Daytona root relay input", () => {
  it("parses one canonical evidence object followed by exactly one framed request", () => {
    const evidence = Object.freeze({
      version: 1,
      kind: "terminalx.daytona-effective-isolation",
      marker: "signed-runner-evidence",
    });
    const evidenceBytes = Buffer.from(canonicalRuntimeJson(evidence), "utf8");
    const frame = requestFrame("relay-request-1");
    const input = relayInput(evidenceBytes, encodeDaytonaSupervisorSocketFrame(frame));

    const parsed = parseFixedDaytonaSupervisorRelayInput(input);
    expect(parsed.evidence).toEqual(evidence);
    expect(parsed.evidenceBytes).toEqual(evidenceBytes);
    expect(parsed.request).toEqual(frame);
    parsed.evidenceBytes.fill(0);
  });

  it("rejects noncanonical and invalid UTF-8 evidence", () => {
    const frame = encodeDaytonaSupervisorSocketFrame(requestFrame("relay-request-2"));
    expect(() =>
      parseFixedDaytonaSupervisorRelayInput(
        relayInput(Buffer.from('{"kind":"evidence"}\n', "utf8"), frame)
      )
    ).toThrow(expect.objectContaining({ code: "invalid-request" }));

    const invalidUtf8 = Buffer.from('{"kind":"x"}', "utf8");
    invalidUtf8[9] = 0xff;
    expect(() => parseFixedDaytonaSupervisorRelayInput(relayInput(invalidUtf8, frame))).toThrow(
      expect.objectContaining({ code: "invalid-request" })
    );
  });

  it("rejects missing, cancel, multiple, incomplete, and trailing frames", () => {
    const evidence = Buffer.from(canonicalRuntimeJson({ kind: "evidence" }), "utf8");
    const request = encodeDaytonaSupervisorSocketFrame(requestFrame("relay-request-3"));
    const cancel = encodeDaytonaSupervisorSocketFrame({
      protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
      version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
      type: "cancel",
      requestId: "relay-request-3",
    });

    for (const frame of [
      Buffer.alloc(0),
      cancel,
      Buffer.concat([request, request]),
      request.subarray(0, request.byteLength - 1),
      Buffer.concat([request, Buffer.from([0])]),
    ]) {
      expect(() => parseFixedDaytonaSupervisorRelayInput(relayInput(evidence, frame))).toThrow(
        expect.objectContaining({ code: "invalid-request" })
      );
    }
  });
});

describe("canonical Daytona supervisor socket decoder", () => {
  it("rejects whitespace and invalid UTF-8 instead of normalizing hostile wire bytes", () => {
    const encoded = encodeDaytonaSupervisorSocketFrame(requestFrame("decoder-request-1"));
    const payload = encoded.subarray(4);
    const whitespacePayload = Buffer.concat([payload, Buffer.from("\n", "utf8")]);
    const whitespaceFrame = Buffer.allocUnsafe(4 + whitespacePayload.byteLength);
    whitespaceFrame.writeUInt32BE(whitespacePayload.byteLength, 0);
    whitespacePayload.copy(whitespaceFrame, 4);
    expect(() => new DaytonaSupervisorSocketFrameDecoder().push(whitespaceFrame)).toThrow(
      expect.objectContaining({ code: "invalid-request" })
    );

    const invalidUtf8 = Buffer.from(encoded);
    const requestIdOffset = invalidUtf8.indexOf(Buffer.from("decoder-request-1", "utf8"));
    expect(requestIdOffset).toBeGreaterThan(3);
    invalidUtf8[requestIdOffset] = 0xff;
    expect(() => new DaytonaSupervisorSocketFrameDecoder().push(invalidUtf8)).toThrow(
      expect.objectContaining({ code: "invalid-request" })
    );
  });
});

function requestFrame(requestId: string) {
  return Object.freeze({
    protocol: DAYTONA_SUPERVISOR_SOCKET_PROTOCOL,
    version: DAYTONA_SUPERVISOR_PROTOCOL_VERSION,
    type: "request" as const,
    requestId,
    method: "isolation.attest" as const,
    params: Object.freeze({ providerSandboxId: PROVIDER_ID }),
  });
}

function relayInput(evidence: Buffer, frame: Buffer): Buffer {
  const prefix = Buffer.allocUnsafe(4);
  prefix.writeUInt32BE(evidence.byteLength, 0);
  return Buffer.concat([prefix, evidence, frame]);
}
