import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  signJwt: vi.fn(),
  consumePairingCode: vi.fn(),
  registerDevice: vi.fn(),
  getAuthMode: vi.fn(),
  resolveAuthenticationIdentity: vi.fn(),
  getUserById: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({ signJwt: mocks.signJwt }));
vi.mock("@/lib/auth-config", () => ({ getAuthMode: mocks.getAuthMode }));
vi.mock("@/lib/identity-service", () => ({
  withCanonicalIdentityAuthority: (operation: (authority: unknown) => unknown) =>
    operation({ resolveAuthenticationIdentity: mocks.resolveAuthenticationIdentity }),
}));
vi.mock("@/lib/pairing", () => ({ consumePairingCode: mocks.consumePairingCode }));
vi.mock("@/lib/devices", () => ({ registerDevice: mocks.registerDevice }));
vi.mock("@/lib/users", () => ({ getUserById: mocks.getUserById }));
vi.mock("@/lib/audit-log", () => ({ audit: vi.fn() }));

describe("mobile pairing canonical identity", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.signJwt.mockResolvedValue("device-token");
    mocks.registerDevice.mockResolvedValue({ id: "device-1" });
    mocks.getAuthMode.mockReturnValue("google");
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
});
