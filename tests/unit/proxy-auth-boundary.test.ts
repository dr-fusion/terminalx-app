import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { proxy } from "@/proxy";

describe("proxy authentication boundary", () => {
  const originalEnvironment = { ...process.env };

  beforeEach(() => {
    process.env.TERMINALX_AUTH_MODE = "local";
    process.env.TERMINALX_JWT_SECRET = "test-secret-that-is-at-least-32-characters";
  });

  afterEach(() => {
    process.env = { ...originalEnvironment };
  });

  it("keeps only the exact pairing redemption endpoint public", async () => {
    const redemption = await proxy(
      new NextRequest("https://terminalx.example/api/auth/pair", { method: "POST" })
    );
    const issuance = await proxy(
      new NextRequest("https://terminalx.example/api/auth/pairing-codes", {
        method: "POST",
      })
    );

    expect(redemption.headers.get("x-middleware-next")).toBe("1");
    expect(issuance.status).toBe(401);
  });

  it("does not allow a public-path prefix to expose another route", async () => {
    const response = await proxy(
      new NextRequest("https://terminalx.example/api/auth/pairing-codes/anything", {
        method: "POST",
      })
    );

    expect(response.status).toBe(401);
  });

  it("rejects spoofed identity headers at sensitive route handlers", async () => {
    const request = new NextRequest("https://terminalx.example/api/auth/pairing-codes", {
      method: "POST",
      headers: {
        "x-user-id": "attacker",
        "x-username": "admin",
        "x-user-role": "admin",
      },
    });
    const { POST: issuePairingCode } = await import("@/app/api/auth/pairing-codes/route");
    const { GET: listDevices } = await import("@/app/api/auth/devices/route");

    const pairingResponse = await issuePairingCode(request);
    const devicesResponse = await listDevices(request);

    expect(pairingResponse.status).toBe(401);
    expect(devicesResponse.status).toBe(401);
  });
});
