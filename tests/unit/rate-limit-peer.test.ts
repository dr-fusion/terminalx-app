import { afterEach, describe, expect, it } from "vitest";
import {
  clientIp,
  isPairingSourceRateLimited,
  isRateLimited,
  stampAuthoritativeDirectPeer,
} from "@/lib/rate-limit";

const DIRECT_PEER_HEADER = "x-terminalx-direct-peer-v1";

function headerBag(values: Record<string, string | undefined>) {
  return {
    get(name: string): string | null {
      return values[name.toLowerCase()] ?? null;
    },
  };
}

afterEach(() => {
  delete process.env.TERMINALX_TRUST_PROXY_HEADERS;
});

describe.sequential("authoritative request peers", () => {
  it("overwrites an untrusted header with the custom server socket peer", () => {
    const headers: Record<string, string | string[] | undefined> = {
      [DIRECT_PEER_HEADER]: "attacker-controlled",
    };
    stampAuthoritativeDirectPeer({ headers, socket: { remoteAddress: "203.0.113.42" } });

    expect(headers[DIRECT_PEER_HEADER]).not.toBe("attacker-controlled");
    expect(clientIp({ headers: headerBag(headers as Record<string, string>) })).toBe(
      "203.0.113.42"
    );
  });

  it("rejects a missing, malformed, or tampered internal peer assertion", () => {
    expect(clientIp({ headers: headerBag({}) })).toBe("unknown");
    expect(clientIp({ headers: headerBag({ [DIRECT_PEER_HEADER]: "attacker-controlled" }) })).toBe(
      "unknown"
    );

    const headers: Record<string, string | string[] | undefined> = {};
    stampAuthoritativeDirectPeer({ headers, socket: { remoteAddress: "2001:db8::7" } });
    const signed = headers[DIRECT_PEER_HEADER] as string;
    const signatureStart = signed.indexOf(".") + 1;
    const tampered = `${signed.slice(0, signatureStart)}${signed[signatureStart] === "A" ? "B" : "A"}${signed.slice(signatureStart + 1)}`;
    expect(clientIp({ headers: headerBag({ [DIRECT_PEER_HEADER]: tampered }) })).toBe("unknown");
  });

  it("uses explicitly trusted proxy headers ahead of the direct proxy peer", () => {
    process.env.TERMINALX_TRUST_PROXY_HEADERS = "true";
    const headers: Record<string, string | string[] | undefined> = {
      "x-forwarded-for": "198.51.100.9, 10.0.0.2",
    };
    stampAuthoritativeDirectPeer({ headers, socket: { remoteAddress: "10.0.0.2" } });

    expect(clientIp({ headers: headerBag(headers as Record<string, string>) })).toBe(
      "198.51.100.9"
    );
  });

  it("rejects a malformed trusted-proxy value and falls back to the signed socket peer", () => {
    process.env.TERMINALX_TRUST_PROXY_HEADERS = "true";
    const headers: Record<string, string | string[] | undefined> = {
      "x-forwarded-for": "attacker-selected-bucket",
      "x-real-ip": "also-not-an-ip",
    };
    stampAuthoritativeDirectPeer({ headers, socket: { remoteAddress: "192.0.2.15" } });

    expect(clientIp({ headers: headerBag(headers as Record<string, string>) })).toBe("192.0.2.15");
  });

  it("bounds unique-code abuse in state that code-key churn cannot evict", () => {
    const peer = "203.0.113.250";
    for (let attempt = 0; attempt < 299; attempt += 1) {
      expect(isPairingSourceRateLimited(peer)).toBe(false);
    }
    for (let key = 0; key < 10_100; key += 1) {
      expect(isRateLimited(`attacker-code-${key}`)).toBe(false);
    }

    expect(isPairingSourceRateLimited(peer)).toBe(false);
    expect(isPairingSourceRateLimited(peer)).toBe(true);
  });

  it("keeps unattributed next:start ingress behind a fixed aggregate ceiling", () => {
    for (let attempt = 0; attempt < 300; attempt += 1) {
      expect(isPairingSourceRateLimited("unknown")).toBe(false);
    }
    expect(isPairingSourceRateLimited("unknown")).toBe(true);
  });
});
