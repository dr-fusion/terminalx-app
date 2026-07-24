import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authMode: "local" as "none" | "password" | "local" | "google",
  verifyJwt: vi.fn(),
}));

vi.mock("@/lib/auth-config", () => ({
  getAuthMode: () => mocks.authMode,
}));

vi.mock("@/lib/auth", () => ({
  parseCookies: (header: string | null) => {
    const result: Record<string, string> = {};
    for (const part of (header ?? "").split(";")) {
      const index = part.indexOf("=");
      if (index < 0) continue;
      result[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
    }
    return result;
  },
  verifyJwt: mocks.verifyJwt,
}));

import { resolveRequestActor, type RequestHeaders } from "@/lib/request-actor";

function headers(values: Record<string, string> = {}): RequestHeaders {
  const normalized = new Map(
    Object.entries(values).map(([name, value]) => [name.toLowerCase(), value])
  );
  return { get: (name) => normalized.get(name.toLowerCase()) ?? null };
}

describe("resolveRequestActor", () => {
  beforeEach(() => {
    mocks.authMode = "local";
    mocks.verifyJwt.mockReset();
  });

  it("does not trust middleware identity headers without a current credential", async () => {
    const actor = await resolveRequestActor(
      headers({ "x-user-id": "stale", "x-username": "stale-admin", "x-user-role": "admin" })
    );

    expect(actor).toBeNull();
    expect(mocks.verifyJwt).not.toHaveBeenCalled();
  });

  it("verifies the session cookie and returns a canonical actor", async () => {
    mocks.verifyJwt.mockResolvedValue({
      userId: "user-1",
      username: "alice",
      role: "user",
    });

    const actor = await resolveRequestActor(
      headers({ cookie: "theme=dark; terminalx-session=current-token" })
    );

    expect(mocks.verifyJwt).toHaveBeenCalledWith("current-token");
    expect(actor).toEqual({
      kind: "human",
      userId: "user-1",
      username: "alice",
      displayName: "alice",
      legacyRole: "user",
    });
  });

  it("supports bearer credentials for API clients", async () => {
    mocks.verifyJwt.mockResolvedValue({
      userId: "user-2",
      username: "bob@example.com",
      role: "admin",
    });

    const actor = await resolveRequestActor(headers({ authorization: "Bearer mobile-token" }));

    expect(mocks.verifyJwt).toHaveBeenCalledWith("mobile-token");
    expect(actor?.userId).toBe("user-2");
  });

  it("prefers the browser cookie when both credential forms are present", async () => {
    mocks.verifyJwt.mockResolvedValue({ userId: "user-1", username: "alice", role: "user" });

    await resolveRequestActor(
      headers({
        cookie: "terminalx-session=cookie-token",
        authorization: "Bearer bearer-token",
      })
    );

    expect(mocks.verifyJwt).toHaveBeenCalledWith("cookie-token");
  });

  it("fails closed when full JWT verification rejects a stale credential", async () => {
    mocks.verifyJwt.mockResolvedValue(null);

    expect(
      await resolveRequestActor(headers({ cookie: "terminalx-session=revoked-token" }))
    ).toBeNull();
  });

  it("fails closed on a malformed cookie header", async () => {
    expect(await resolveRequestActor(headers({ cookie: "terminalx-session=%" }))).toBeNull();
    expect(mocks.verifyJwt).not.toHaveBeenCalled();
  });

  it("retains the unsupported auth-none development actor without trusting headers", async () => {
    mocks.authMode = "none";

    const actor = await resolveRequestActor(headers({ "x-user-id": "spoofed" }));

    expect(actor?.userId).toBe("single-user");
    expect(mocks.verifyJwt).not.toHaveBeenCalled();
  });
});
