import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  signJwt: vi.fn(),
  consumePairingCode: vi.fn(),
  registerDevice: vi.fn(),
  revokeDevice: vi.fn(),
  getAuthMode: vi.fn(),
  isEmailAllowed: vi.fn(),
  resolveAuthenticationIdentity: vi.fn(),
  getLocalAuthenticationIdentity: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({ signJwt: mocks.signJwt }));
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
  revokeDevice: mocks.revokeDevice,
}));
vi.mock("@/lib/users", () => ({
  getLocalAuthenticationIdentity: mocks.getLocalAuthenticationIdentity,
}));
vi.mock("@/lib/audit-log", () => ({ audit: vi.fn() }));
vi.mock("@/lib/rate-limit", () => ({ isRateLimited: () => false }));

describe("mobile pairing canonical identity", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.signJwt.mockResolvedValue("device-token");
    mocks.registerDevice.mockResolvedValue({ id: "device-1" });
    mocks.revokeDevice.mockResolvedValue(true);
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
    mocks.getLocalAuthenticationIdentity.mockReturnValue(null);
    mocks.consumePairingCode.mockResolvedValue({
      userId: "user-1",
      username: "alice@example.com",
      displayName: "Alice",
      role: "admin",
      authProvider: "google",
      authSubject: "google-subject-1",
      userGeneration: 4,
      authIdentityGeneration: 2,
    });
  });

  it("copies the exact verified identity generations into the device JWT", async () => {
    const { POST } = await import("@/app/api/auth/pair/route");
    const response = await POST({
      json: async () => ({ code: "pair-code", deviceName: "Phone" }),
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
      deviceId: "device-1",
    });
  });

  it("consumes but rejects a code whose canonical identity was revoked before redemption", async () => {
    mocks.resolveAuthenticationIdentity.mockReturnValue(null);
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: "pair-code", deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("rejects a canonical pairing snapshot after the authentication mode changes", async () => {
    mocks.getAuthMode.mockReturnValue("local");
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: "pair-code", deviceName: "Phone" }),
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
      json: async () => ({ code: "pair-code", deviceName: "Phone" }),
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
      json: async () => ({ code: "pair-code", deviceName: "Phone" }),
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
      json: async () => ({ code: "pair-code", deviceName: "Phone" }),
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
      json: async () => ({ code: "pair-code", deviceName: "Phone" }),
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
      json: async () => ({ code: "pair-code", deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(401);
    expect(mocks.registerDevice).not.toHaveBeenCalled();
    expect(mocks.signJwt).not.toHaveBeenCalled();
  });

  it("upgrades a legacy local pairing code to a canonical device JWT", async () => {
    mocks.getAuthMode.mockReturnValue("local");
    mocks.consumePairingCode.mockResolvedValue({
      userId: "legacy-local-user",
      username: "alice",
      role: "user",
    });
    mocks.getLocalAuthenticationIdentity.mockReturnValue({
      user: {
        id: "legacy-local-user",
        username: "alice",
        displayName: "Alice",
        legacyRole: "user",
        generation: 3,
      },
      identity: {
        provider: "local",
        subject: "legacy-local-user",
        generation: 2,
      },
    });
    const { POST } = await import("@/app/api/auth/pair/route");

    const response = await POST({
      json: async () => ({ code: "pair-code", deviceName: "Phone" }),
      headers: { get: () => null },
    } as never);

    expect(response.status).toBe(200);
    expect(mocks.signJwt).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "legacy-local-user",
        authProvider: "local",
        authSubject: "legacy-local-user",
        userGeneration: 3,
        authIdentityGeneration: 2,
      })
    );
  });
});
