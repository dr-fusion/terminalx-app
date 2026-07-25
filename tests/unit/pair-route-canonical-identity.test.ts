import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

const SOURCE_CREDENTIAL_EXPIRES_AT_MS = 4_000_000_000_000;
const PAIRING_CODE = "A".repeat(32);

const mocks = vi.hoisted(() => ({
  signJwt: vi.fn(),
  consumePairingCode: vi.fn(),
  registerDevice: vi.fn(),
  getDevice: vi.fn(),
  revokeDevice: vi.fn(),
  getAuthMode: vi.fn(),
  isEmailAllowed: vi.fn(),
  resolveAuthenticationIdentity: vi.fn(),
  isStoredAuthenticationSessionActive: vi.fn(),
  audit: vi.fn(),
  isRateLimited: vi.fn(),
  isPairingSourceRateLimited: vi.fn(),
  clientIp: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({ signJwtWithMetadata: mocks.signJwt }));
vi.mock("@/lib/auth-config", () => ({
  getAuthMode: mocks.getAuthMode,
  isEmailAllowed: mocks.isEmailAllowed,
}));
vi.mock("@/lib/identity-service", () => ({
  withCanonicalIdentityAuthority: (operation: (authority: unknown) => unknown) =>
    operation({ resolveAuthenticationIdentity: mocks.resolveAuthenticationIdentity }),
}));
vi.mock("@/lib/pairing", () => ({ consumePairingCode: mocks.consumePairingCode }));
vi.mock("@/lib/devices", () => ({
  registerDevice: mocks.registerDevice,
  getDevice: mocks.getDevice,
  revokeDevice: mocks.revokeDevice,
}));
vi.mock("@/lib/auth-session-snapshot", () => ({
  isStoredAuthenticationSessionActive: mocks.isStoredAuthenticationSessionActive,
}));
vi.mock("@/lib/audit-log", () => ({ audit: mocks.audit }));
vi.mock("@/lib/rate-limit", () => ({
  isRateLimited: mocks.isRateLimited,
  isPairingSourceRateLimited: mocks.isPairingSourceRateLimited,
  clientIp: mocks.clientIp,
}));

describe("mobile pairing canonical identity", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.signJwt.mockResolvedValue({
      token: "device-token",
      issuedAtMs: 1_900_000_000_000,
      expiresAtMs: 1_900_086_400_000,
    });
    mocks.registerDevice.mockResolvedValue({ id: "device-1" });
    mocks.getDevice.mockResolvedValue({
      id: "device-1",
      userId: "user-1",
      username: "alice@example.com",
      name: "Phone",
      createdAt: 1_900_000_000_000,
      lastSeenAt: 1_900_000_000_000,
      revokedAt: null,
    });
    mocks.revokeDevice.mockResolvedValue(true);
    mocks.isRateLimited.mockReturnValue(false);
    mocks.isPairingSourceRateLimited.mockReturnValue(false);
    mocks.clientIp.mockReturnValue("unknown");
    mocks.getAuthMode.mockReturnValue("google");
    mocks.isEmailAllowed.mockReturnValue(true);
    mocks.resolveAuthenticationIdentity.mockReturnValue({
      user: {
        id: "user-1",
        username: "alice@example.com",
        displayName: "Alice",
        legacyRole: "admin",
        generation: 4,
      },
      identity: {
        provider: "google",
        subject: "google-subject-1",
        generation: 2,
      },
    });
    mocks.isStoredAuthenticationSessionActive.mockReturnValue(true);
    mocks.consumePairingCode.mockResolvedValue({
      userId: "user-1",
      username: "alice@example.com",
      displayName: "Alice",
      role: "admin",
      authProvider: "google",
      authSubject: "google-subject-1",
      userGeneration: 4,
      authIdentityGeneration: 2,
      authTime: 1_700_000_000,
      sourceAuthentication: {
        credentialJtiDigest: "a".repeat(64),
        credentialExpiresAtMs: SOURCE_CREDENTIAL_EXPIRES_AT_MS,
        device: { provenance: "browser" },
      },
    });
  });

  it("copies the exact verified identity generations into the device JWT", async () => {
    const { POST } = await import("@/app/api/auth/pair/route");
    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(200);
    expect(mocks.signJwt).toHaveBeenCalledWith({
      userId: "user-1",
      username: "alice@example.com",
      displayName: "Alice",
      role: "admin",
      authProvider: "google",
      authSubject: "google-subject-1",
      userGeneration: 4,
      authIdentityGeneration: 2,
      authTime: 1_700_000_000,
      deviceId: "device-1",
    });
    await expect(response.json()).resolves.toMatchObject({
      token: "device-token",
      expiresAt: 1_900_086_400_000,
    });
    expect(mocks.audit).toHaveBeenCalledWith("pair_success", {
      username: "alice@example.com",
      userId: "user-1",
    });
    expect(JSON.stringify(mocks.audit.mock.calls)).not.toContain("device-1");
  });

  it("returns 503 without registering a device when the exclusive claim is unavailable", async () => {
    mocks.consumePairingCode.mockRejectedValue(new Error("claim storage unavailable"));
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(mocks.registerDevice).not.toHaveBeenCalled();
  });

  it("rejects malformed codes before rate limiting or authority access", async () => {
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: "not a pairing code", deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(400);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(mocks.clientIp).toHaveBeenCalledTimes(1);
    expect(mocks.isPairingSourceRateLimited).toHaveBeenCalledWith("unknown");
    expect(mocks.isRateLimited).not.toHaveBeenCalled();
    expect(mocks.consumePairingCode).not.toHaveBeenCalled();
  });

  it("uses only a pairing-code digest when no authoritative peer is available", async () => {
    mocks.isRateLimited.mockReturnValueOnce(true);
    const expectedDigest = createHash("sha256").update(PAIRING_CODE, "utf8").digest("hex");
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(429);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("retry-after")).toBe("60");
    expect(mocks.isRateLimited).toHaveBeenCalledWith(`pair:code:${expectedDigest}`);
    expect(mocks.isRateLimited.mock.calls[0]![0]).not.toContain(PAIRING_CODE);
    expect(JSON.stringify(mocks.audit.mock.calls)).not.toContain(PAIRING_CODE);
    expect(JSON.stringify(mocks.audit.mock.calls)).not.toContain(expectedDigest);
    expect(mocks.consumePairingCode).not.toHaveBeenCalled();
  });

  it("does not let a shared proxy peer create a cross-code bucket", async () => {
    mocks.clientIp.mockReturnValueOnce("203.0.113.9");
    mocks.isRateLimited.mockReturnValueOnce(true);
    const expectedDigest = createHash("sha256").update(PAIRING_CODE, "utf8").digest("hex");
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(429);
    expect(mocks.isRateLimited).toHaveBeenCalledWith(`pair:code:${expectedDigest}`);
    expect(mocks.isRateLimited).not.toHaveBeenCalledWith("pair:direct-client");
    expect(mocks.clientIp).toHaveBeenCalledTimes(1);
    expect(mocks.consumePairingCode).not.toHaveBeenCalled();
  });

  it("stops unique-code resource abuse in a separate source bucket", async () => {
    mocks.clientIp.mockReturnValueOnce("203.0.113.9");
    mocks.isPairingSourceRateLimited.mockReturnValueOnce(true);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("60");
    expect(mocks.isPairingSourceRateLimited).toHaveBeenCalledWith("203.0.113.9");
    expect(mocks.isRateLimited).not.toHaveBeenCalled();
    expect(mocks.consumePairingCode).not.toHaveBeenCalled();
  });

  it("returns an audited retryable failure when registration fails after consumption", async () => {
    mocks.registerDevice.mockRejectedValueOnce(new Error("device storage unavailable"));
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toContain("no-store");
    await expect(response.json()).resolves.toEqual({
      error:
        "Pairing could not be completed after the code was consumed. Generate a new pairing code and try again.",
    });
    expect(mocks.audit).toHaveBeenCalledWith("pair_failed", {
      username: "alice@example.com",
      userId: "user-1",
      detail: "device registration failed after pairing code consumption",
    });
    expect(mocks.getDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it.each([
    ["missing", null],
    [
      "revoked",
      {
        id: "device-1",
        userId: "user-1",
        username: "alice@example.com",
        revokedAt: 1_900_000_000_001,
      },
    ],
    [
      "owned by another user",
      {
        id: "device-1",
        userId: "user-2",
        username: "mallory@example.com",
        revokedAt: null,
      },
    ],
  ])("withholds a token when the new device is %s before signing", async (_case, stored) => {
    mocks.getDevice.mockResolvedValueOnce(stored);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(mocks.getDevice).toHaveBeenCalledWith("device-1");
    expect(mocks.revokeDevice).toHaveBeenCalledWith("device-1", "user-1");
    expect(mocks.signJwt).not.toHaveBeenCalled();
    expect(mocks.audit).toHaveBeenCalledWith("pair_failed", {
      username: "alice@example.com",
      userId: "user-1",
      detail: "device registration durability recheck failed",
    });
    await expect(response.json()).resolves.not.toHaveProperty("token");
  });

  it("withholds a signed token when the device disappears after signing", async () => {
    mocks.getDevice
      .mockResolvedValueOnce({
        id: "device-1",
        userId: "user-1",
        username: "alice@example.com",
        revokedAt: null,
      })
      .mockResolvedValueOnce(null);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(mocks.getDevice).toHaveBeenCalledTimes(2);
    expect(mocks.signJwt).toHaveBeenCalledOnce();
    expect(mocks.revokeDevice).toHaveBeenCalledWith("device-1", "user-1");
    expect(mocks.audit).toHaveBeenCalledWith("pair_failed", {
      username: "alice@example.com",
      userId: "user-1",
      detail: "device registration recheck failed after credential signing",
    });
    await expect(response.json()).resolves.not.toHaveProperty("token");
  });

  it("rejects a pairing code with a future primary-authentication time", async () => {
    mocks.consumePairingCode.mockResolvedValue({
      userId: "user-1",
      username: "alice@example.com",
      displayName: "Alice",
      role: "admin",
      authProvider: "google",
      authSubject: "google-subject-1",
      userGeneration: 4,
      authIdentityGeneration: 2,
      authTime: Math.floor(Date.now() / 1000) + 60,
      sourceAuthentication: {
        credentialJtiDigest: "a".repeat(64),
        credentialExpiresAtMs: SOURCE_CREDENTIAL_EXPIRES_AT_MS,
        device: { provenance: "browser" },
      },
    });
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("rejects redemption after the source browser credential is logged out", async () => {
    mocks.isStoredAuthenticationSessionActive.mockReturnValue(false);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.isStoredAuthenticationSessionActive).toHaveBeenCalledWith({
      canonicalUserId: "user-1",
      canonicalUsername: "alice@example.com",
      provider: "google",
      credentialJtiDigest: "a".repeat(64),
      credentialExpiresAtMs: SOURCE_CREDENTIAL_EXPIRES_AT_MS,
      device: { provenance: "browser" },
    });
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("rejects redemption after the source paired device is revoked", async () => {
    mocks.consumePairingCode.mockResolvedValue({
      userId: "user-1",
      username: "alice@example.com",
      displayName: "Alice",
      role: "admin",
      authProvider: "google",
      authSubject: "google-subject-1",
      userGeneration: 4,
      authIdentityGeneration: 2,
      authTime: 1_700_000_000,
      sourceAuthentication: {
        credentialJtiDigest: "b".repeat(64),
        credentialExpiresAtMs: SOURCE_CREDENTIAL_EXPIRES_AT_MS,
        device: { provenance: "paired-device", id: "source-device-1" },
      },
    });
    mocks.isStoredAuthenticationSessionActive.mockReturnValue(false);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.isStoredAuthenticationSessionActive).toHaveBeenCalledWith(
      expect.objectContaining({
        credentialJtiDigest: "b".repeat(64),
        device: { provenance: "paired-device", id: "source-device-1" },
      })
    );
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("revokes the new device when the source session changes during registration", async () => {
    mocks.isStoredAuthenticationSessionActive.mockReturnValueOnce(true).mockReturnValueOnce(false);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.registerDevice).toHaveBeenCalledOnce();
    expect(mocks.isStoredAuthenticationSessionActive).toHaveBeenCalledTimes(2);
    expect(mocks.revokeDevice).toHaveBeenCalledWith("device-1", "user-1");
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("revokes the new device when the source session changes during credential signing", async () => {
    mocks.isStoredAuthenticationSessionActive
      .mockReturnValueOnce(true)
      .mockReturnValueOnce(true)
      .mockReturnValueOnce(false);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.registerDevice).toHaveBeenCalledOnce();
    expect(mocks.signJwt).toHaveBeenCalledOnce();
    expect(mocks.isStoredAuthenticationSessionActive).toHaveBeenCalledTimes(3);
    expect(mocks.revokeDevice).toHaveBeenCalledWith("device-1", "user-1");
    await expect(response.json()).resolves.not.toHaveProperty("token");
  });

  it("consumes but rejects a code whose canonical identity was revoked before redemption", async () => {
    mocks.resolveAuthenticationIdentity.mockReturnValue(null);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("returns a controlled 503 when identity authority fails after code consumption", async () => {
    mocks.resolveAuthenticationIdentity.mockImplementationOnce(() => {
      throw new Error("identity database unavailable");
    });
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
    expect(mocks.audit).toHaveBeenCalledWith("pair_failed", {
      detail: "pairing identity authority unavailable after consumption",
    });
  });

  it("revokes a registered device when the identity authority becomes unavailable", async () => {
    const canonical = mocks.resolveAuthenticationIdentity();
    mocks.resolveAuthenticationIdentity.mockClear();
    mocks.resolveAuthenticationIdentity
      .mockReturnValueOnce(canonical)
      .mockImplementationOnce(() => {
        throw new Error("identity database unavailable");
      });
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(503);
    expect(mocks.revokeDevice).toHaveBeenCalledWith("device-1", "user-1");
    expect(mocks.signJwt).not.toHaveBeenCalled();
    await expect(response.json()).resolves.not.toHaveProperty("token");
  });

  it("revokes the device and withholds a signed token when final identity resolution fails", async () => {
    const canonical = mocks.resolveAuthenticationIdentity();
    mocks.resolveAuthenticationIdentity.mockClear();
    mocks.resolveAuthenticationIdentity
      .mockReturnValueOnce(canonical)
      .mockReturnValueOnce(canonical)
      .mockImplementationOnce(() => {
        throw new Error("identity database unavailable");
      });
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(503);
    expect(mocks.signJwt).toHaveBeenCalledOnce();
    expect(mocks.revokeDevice).toHaveBeenCalledWith("device-1", "user-1");
    await expect(response.json()).resolves.not.toHaveProperty("token");
  });

  it("rejects a canonical pairing snapshot after the authentication mode changes", async () => {
    mocks.getAuthMode.mockReturnValue("local");
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.resolveAuthenticationIdentity).not.toHaveBeenCalled();
    expect(mocks.registerDevice).not.toHaveBeenCalled();
  });

  it("rejects a Google pairing snapshot after its email leaves the allowlist", async () => {
    mocks.isEmailAllowed.mockReturnValue(false);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("revokes the device when the identity changes during registration", async () => {
    mocks.resolveAuthenticationIdentity
      .mockReturnValueOnce({
        user: {
          id: "user-1",
          username: "alice@example.com",
          displayName: "Alice",
          legacyRole: "admin",
          generation: 4,
        },
        identity: {
          provider: "google",
          subject: "google-subject-1",
          generation: 2,
        },
      })
      .mockReturnValueOnce(null);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.registerDevice).toHaveBeenCalledOnce();
    expect(mocks.revokeDevice).toHaveBeenCalledWith("device-1", "user-1");
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("revokes the device when canonical token issuance fails", async () => {
    mocks.signJwt.mockRejectedValueOnce(new Error("auth mode changed"));
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.revokeDevice).toHaveBeenCalledWith("device-1", "user-1");
  });

  it("rejects a legacy shared-password code instead of minting an unscoped device token", async () => {
    mocks.getAuthMode.mockReturnValue("password");
    mocks.consumePairingCode.mockResolvedValue({
      userId: "single-user",
      username: "admin",
      role: "admin",
    });
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("does not mint unscoped device JWTs in development no-auth mode", async () => {
    mocks.getAuthMode.mockReturnValue("none");
    mocks.consumePairingCode.mockResolvedValue({
      userId: "single-user",
      username: "admin",
      role: "admin",
    });
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("rejects a source-less legacy local pairing code and requires re-login", async () => {
    mocks.getAuthMode.mockReturnValue("local");
    mocks.consumePairingCode.mockResolvedValue({
      userId: "legacy-local-user",
      username: "alice",
      role: "user",
    });
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: PAIRING_CODE, deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.resolveAuthenticationIdentity).not.toHaveBeenCalled();
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });
});
