import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  authMode: "local" as "none" | "password" | "local" | "google",
  emailAllowed: true,
  digestActive: true,
  getDevice: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({
  isJwtIdentifierDigestActive: (digest: string) => mocks.digestActive && digest === "a".repeat(64),
}));

vi.mock("@/lib/auth-config", () => ({
  getAuthMode: () => mocks.authMode,
  isEmailAllowed: () => mocks.emailAllowed,
}));

vi.mock("@/lib/devices", () => ({
  getDevice: mocks.getDevice,
}));

import {
  isStoredAuthenticationSessionActive,
  type StoredAuthenticationSessionSnapshot,
} from "@/lib/auth-session-snapshot";

const browserSnapshot: StoredAuthenticationSessionSnapshot = {
  canonicalUserId: "user-1",
  canonicalUsername: "alice",
  provider: "local",
  credentialJtiDigest: "a".repeat(64),
  credentialExpiresAtMs: Date.now() + 60_000,
  device: { provenance: "browser" },
};

describe("stored authentication-session snapshots", () => {
  beforeEach(() => {
    mocks.authMode = "local";
    mocks.emailAllowed = true;
    mocks.digestActive = true;
    mocks.getDevice.mockReset();
  });

  it("accepts an unrevoked browser credential in the current authentication mode", () => {
    expect(isStoredAuthenticationSessionActive(browserSnapshot)).toBe(true);
    expect(mocks.getDevice).not.toHaveBeenCalled();
  });

  it("fails closed after the authentication mode changes or becomes disabled", () => {
    mocks.authMode = "password";
    expect(isStoredAuthenticationSessionActive(browserSnapshot)).toBe(false);

    mocks.authMode = "none";
    expect(isStoredAuthenticationSessionActive(browserSnapshot)).toBe(false);
  });

  it("rechecks the current Google allowlist at completion", () => {
    mocks.authMode = "google";
    const snapshot = {
      ...browserSnapshot,
      provider: "google" as const,
      canonicalUsername: "alice@example.com",
    };

    expect(isStoredAuthenticationSessionActive(snapshot)).toBe(true);
    mocks.emailAllowed = false;
    expect(isStoredAuthenticationSessionActive(snapshot)).toBe(false);
  });

  it("fails closed when the digest-only credential snapshot is revoked or malformed", () => {
    mocks.digestActive = false;
    expect(isStoredAuthenticationSessionActive(browserSnapshot)).toBe(false);

    mocks.digestActive = true;
    expect(
      isStoredAuthenticationSessionActive({
        ...browserSnapshot,
        credentialJtiDigest: "not-a-sha256-digest",
      })
    ).toBe(false);
  });

  it("fails closed when the source credential expires", () => {
    expect(
      isStoredAuthenticationSessionActive({
        ...browserSnapshot,
        credentialExpiresAtMs: Date.now() - 1,
      })
    ).toBe(false);
  });

  it("requires a paired device to be active and owned by the canonical User", () => {
    const snapshot: StoredAuthenticationSessionSnapshot = {
      ...browserSnapshot,
      device: { provenance: "paired-device", id: "device-1" },
    };
    mocks.getDevice.mockReturnValue({
      id: "device-1",
      userId: "user-1",
      username: "alice",
      name: "Alice phone",
      createdAt: 1,
      lastSeenAt: 1,
      revokedAt: null,
    });
    expect(isStoredAuthenticationSessionActive(snapshot)).toBe(true);

    mocks.getDevice.mockReturnValue({
      id: "device-1",
      userId: "user-2",
      username: "mallory",
      name: "Other phone",
      createdAt: 1,
      lastSeenAt: 1,
      revokedAt: null,
    });
    expect(isStoredAuthenticationSessionActive(snapshot)).toBe(false);

    mocks.getDevice.mockReturnValue({
      id: "device-1",
      userId: "user-1",
      username: "alice",
      name: "Alice phone",
      createdAt: 1,
      lastSeenAt: 1,
      revokedAt: 2,
    });
    expect(isStoredAuthenticationSessionActive(snapshot)).toBe(false);

    mocks.getDevice.mockReturnValue(null);
    expect(isStoredAuthenticationSessionActive(snapshot)).toBe(false);
  });

  it("rejects ambiguous or hostile provenance shapes without throwing", () => {
    expect(
      isStoredAuthenticationSessionActive({
        ...browserSnapshot,
        device: { provenance: "browser", id: "smuggled-device" },
      } as never)
    ).toBe(false);
    expect(
      isStoredAuthenticationSessionActive({
        ...browserSnapshot,
        device: { provenance: "paired-device" },
      } as never)
    ).toBe(false);
    expect(isStoredAuthenticationSessionActive(null as never)).toBe(false);
  });
});
