import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

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
    delete process.env.TERMINALX_AUTH_MODE;
    delete process.env.TERMINALX_ALLOW_AUTH_NONE;
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
      displayName: "Alice Example",
      role: "user",
      authProvider: "google",
      authSubject: "google-subject-1",
      userGeneration: 3,
      authIdentityGeneration: 2,
      authTime: 1_700_000_000,
      iat: 1_700_000_100,
      exp: 2_000_000_000,
      jti: "raw-session-jti",
    });

    const actor = await resolveRequestActor(
      headers({ cookie: "theme=dark; terminalx-session=current-token" })
    );

    expect(mocks.verifyJwt).toHaveBeenCalledWith("current-token");
    expect(actor).toEqual({
      kind: "human",
      userId: "user-1",
      username: "alice",
      displayName: "Alice Example",
      legacyRole: "user",
      authentication: {
        provider: "google",
        subject: "google-subject-1",
        userGeneration: 3,
        identityGeneration: 2,
        authenticatedAtMs: 1_700_000_000_000,
        credentialIssuedAtMs: 1_700_000_100_000,
        credentialExpiresAtMs: 2_000_000_000_000,
        credentialJtiDigest: createHash("sha256").update("raw-session-jti").digest("hex"),
        device: { provenance: "browser" },
      },
    });
    expect(JSON.stringify(actor)).not.toContain("raw-session-jti");
  });

  it("preserves missing auth_time and reports signed paired-device provenance", async () => {
    mocks.verifyJwt.mockResolvedValue({
      userId: "user-1",
      username: "alice",
      role: "user",
      authProvider: "local",
      authSubject: "alice",
      userGeneration: 1,
      authIdentityGeneration: 1,
      iat: 1_700_000_100,
      exp: 2_000_000_000,
      jti: "paired-session-jti",
      deviceId: "device-7",
    });

    const actor = await resolveRequestActor(headers({ authorization: "Bearer paired-token" }));

    expect(actor?.authentication).toEqual({
      provider: "local",
      subject: "alice",
      userGeneration: 1,
      identityGeneration: 1,
      credentialIssuedAtMs: 1_700_000_100_000,
      credentialExpiresAtMs: 2_000_000_000_000,
      credentialJtiDigest: createHash("sha256").update("paired-session-jti").digest("hex"),
      device: { provenance: "paired-device", id: "device-7" },
    });
    expect(actor?.authentication).not.toHaveProperty("authenticatedAtMs");
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

  it("fails closed when auth-none lacks the separate explicit opt-in", async () => {
    mocks.authMode = "none";

    const actor = await resolveRequestActor(headers({ "x-user-id": "spoofed" }));

    expect(actor).toBeNull();
    expect(mocks.verifyJwt).not.toHaveBeenCalled();
  });

  it("retains the explicit auth-none development actor without trusting headers", async () => {
    mocks.authMode = "none";
    process.env.TERMINALX_AUTH_MODE = "none";
    process.env.TERMINALX_ALLOW_AUTH_NONE = "true";

    const actor = await resolveRequestActor(headers({ "x-user-id": "spoofed" }));

    expect(actor?.userId).toBe("single-user");
    expect(mocks.verifyJwt).not.toHaveBeenCalled();
  });
});
