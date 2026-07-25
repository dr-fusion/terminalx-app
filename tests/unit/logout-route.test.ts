import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  revokeToken: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({
  revokeToken: mocks.revokeToken,
}));

vi.mock("@/lib/audit-log", () => ({ audit: vi.fn() }));

describe("logout route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.revokeToken.mockResolvedValue(null);
  });

  it("revokes a valid bearer token", async () => {
    mocks.revokeToken.mockResolvedValue({
      status: "persisted",
      userId: "user-1",
      username: "alice",
      expiresAtMs: 2_000_000_000_000,
    });
    const request = new NextRequest("https://terminalx.example/api/auth/logout", {
      method: "POST",
      headers: { authorization: "Bearer valid-token" },
    });
    const { POST } = await import("@/app/api/auth/logout/route");

    const response = await POST(request);

    expect(response.status).toBe(200);
    expect(mocks.revokeToken).toHaveBeenCalledWith("valid-token");
    expect(response.headers.get("cache-control")).toContain("no-store");
  });

  it("clears an invalid credential without accepting an attacker-controlled tombstone", async () => {
    const request = new NextRequest("https://terminalx.example/api/auth/logout", {
      method: "POST",
      headers: { authorization: "Bearer attacker-controlled-token" },
    });
    const { POST } = await import("@/app/api/auth/logout/route");

    const response = await POST(request);

    expect(response.status).toBe(200);
    expect(mocks.revokeToken).toHaveBeenCalledWith("attacker-controlled-token");
    expect(response.headers.get("set-cookie")).toContain("Max-Age=0");
  });

  it("does not claim success or clear the cookie when durable revocation fails", async () => {
    mocks.revokeToken.mockRejectedValue(new Error("disk unavailable"));
    const request = new NextRequest("https://terminalx.example/api/auth/logout", {
      method: "POST",
      headers: { cookie: "terminalx-session=valid-token" },
    });
    const { POST } = await import("@/app/api/auth/logout/route");

    const response = await POST(request);

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      success: false,
      error: "Logout could not be completed safely. Try again.",
    });
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("set-cookie")).toBeNull();
  });
});
