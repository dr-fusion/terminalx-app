import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  resolveRequestActor: vi.fn(),
  createPairingCode: vi.fn(),
  audit: vi.fn(),
}));

vi.mock("@/lib/request-actor", () => ({
  resolveRequestActor: mocks.resolveRequestActor,
}));
vi.mock("@/lib/pairing", () => ({
  createPairingCode: mocks.createPairingCode,
}));
vi.mock("@/lib/audit-log", () => ({ audit: mocks.audit }));

describe("pairing-code recent authentication", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.createPairingCode.mockResolvedValue({ code: "code-1", expiresAt: 1_700_000_120_000 });
    mocks.resolveRequestActor.mockResolvedValue({
      kind: "human",
      userId: "user-1",
      username: "alice@example.com",
      displayName: "Alice",
      legacyRole: "admin",
      authentication: {
        provider: "google",
        subject: "google-subject-1",
        userGeneration: 4,
        identityGeneration: 2,
        authenticatedAtMs: 1_700_000_000_000,
        credentialIssuedAtMs: 1_700_000_100_000,
        credentialExpiresAtMs: 4_000_000_000_000,
        credentialJtiDigest: "a".repeat(64),
        device: { provenance: "browser" },
      },
    });
  });

  it("copies the signed primary auth_time rather than the credential iat", async () => {
    const { POST } = await import("@/app/api/auth/pairing-codes/route");

    const response = await POST({ headers: new Headers() } as never);

    expect(response.status).toBe(200);
    expect(mocks.createPairingCode).toHaveBeenCalledWith(
      expect.objectContaining({
        authTime: 1_700_000_000,
        sourceAuthentication: {
          credentialJtiDigest: "a".repeat(64),
          credentialExpiresAtMs: 4_000_000_000_000,
          device: { provenance: "browser" },
        },
      })
    );
    expect(mocks.createPairingCode.mock.calls[0]![0].authTime).not.toBe(1_700_000_100);
  });

  it("preserves absence for credentials that predate auth_time", async () => {
    const actor = await mocks.resolveRequestActor();
    delete actor.authentication.authenticatedAtMs;
    mocks.resolveRequestActor.mockResolvedValue(actor);
    const { POST } = await import("@/app/api/auth/pairing-codes/route");

    const response = await POST({ headers: new Headers() } as never);

    expect(response.status).toBe(200);
    expect(mocks.createPairingCode.mock.calls[0]![0]).not.toHaveProperty("authTime");
  });

  it("returns 503 instead of publishing a code when durable storage is unavailable", async () => {
    mocks.createPairingCode.mockRejectedValue(new Error("storage unavailable"));
    const { POST } = await import("@/app/api/auth/pairing-codes/route");

    const response = await POST({ headers: new Headers() } as never);

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toContain("no-store");
    await expect(response.json()).resolves.toEqual({
      error: "Pairing state is temporarily unavailable. Try again.",
    });
    expect(mocks.audit).toHaveBeenCalledWith("pair_failed", {
      username: "alice@example.com",
      userId: "user-1",
      detail: "pairing code persistence unavailable",
    });
    expect(mocks.audit).not.toHaveBeenCalledWith("pairing_code_created", expect.anything());
  });

  it("maps a typed issuance limit to an audited retryable 429", async () => {
    const limit = Object.assign(new Error("issuance limit reached"), {
      name: "PairingIssuanceLimitError",
      code: "PAIRING_ISSUANCE_LIMIT",
      retryAfterSeconds: 37,
    });
    mocks.createPairingCode.mockRejectedValue(limit);
    const { POST } = await import("@/app/api/auth/pairing-codes/route");

    const response = await POST({ headers: new Headers() } as never);

    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("37");
    expect(response.headers.get("cache-control")).toContain("no-store");
    await expect(response.json()).resolves.toEqual({
      error: "Too many pairing codes requested. Try again later.",
    });
    expect(mocks.audit).toHaveBeenCalledWith("rate_limited", {
      username: "alice@example.com",
      userId: "user-1",
      detail: "pairing code issuance",
    });
    expect(mocks.audit).not.toHaveBeenCalledWith("pairing_code_created", expect.anything());
  });

  it("does not trust an untyped retry-after value from a storage error", async () => {
    mocks.createPairingCode.mockRejectedValue(
      Object.assign(new Error("storage unavailable"), { retryAfterSeconds: 30 })
    );
    const { POST } = await import("@/app/api/auth/pairing-codes/route");

    const response = await POST({ headers: new Headers() } as never);

    expect(response.status).toBe(503);
    expect(response.headers.get("retry-after")).toBeNull();
    expect(response.headers.get("cache-control")).toContain("no-store");
  });

  it("requires re-login instead of issuing a source-less legacy pairing code", async () => {
    mocks.resolveRequestActor.mockResolvedValue({
      kind: "human",
      userId: "legacy-local-user",
      username: "alice",
      displayName: "Alice",
      legacyRole: "user",
    });
    const { POST } = await import("@/app/api/auth/pairing-codes/route");

    const response = await POST({ headers: new Headers() } as never);

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(mocks.createPairingCode).not.toHaveBeenCalled();
  });
});
