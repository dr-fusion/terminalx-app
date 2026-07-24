import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  revokeToken: vi.fn(),
  verifyJwt: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({
  revokeToken: mocks.revokeToken,
  verifyJwt: mocks.verifyJwt,
}));

vi.mock("@/lib/audit-log", () => ({ audit: vi.fn() }));

describe("logout route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("revokes a valid bearer token", async () => {
    mocks.verifyJwt.mockResolvedValue({
      userId: "user-1",
      username: "alice",
      role: "user",
    });
    const request = new NextRequest("https://terminalx.example/api/auth/logout", {
      method: "POST",
      headers: { authorization: "Bearer valid-token" },
    });
    const { POST } = await import("@/app/api/auth/logout/route");

    const response = await POST(request);

    expect(response.status).toBe(200);
    expect(mocks.verifyJwt).toHaveBeenCalledWith("valid-token");
    expect(mocks.revokeToken).toHaveBeenCalledWith("valid-token");
    expect(response.headers.get("cache-control")).toContain("no-store");
  });

  it("does not persist attacker-controlled revocation entries", async () => {
    mocks.verifyJwt.mockResolvedValue(null);
    const request = new NextRequest("https://terminalx.example/api/auth/logout", {
      method: "POST",
      headers: { authorization: "Bearer attacker-controlled-token" },
    });
    const { POST } = await import("@/app/api/auth/logout/route");

    const response = await POST(request);

    expect(response.status).toBe(200);
    expect(mocks.revokeToken).not.toHaveBeenCalled();
  });
});
