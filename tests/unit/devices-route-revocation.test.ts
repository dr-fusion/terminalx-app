import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  resolveRequestActor: vi.fn(),
  revokeDevice: vi.fn(),
  listDevicesForUser: vi.fn(),
  audit: vi.fn(),
}));

vi.mock("@/lib/request-actor", () => ({
  resolveRequestActor: mocks.resolveRequestActor,
}));

vi.mock("@/lib/devices", () => ({
  revokeDevice: mocks.revokeDevice,
  listDevicesForUser: mocks.listDevicesForUser,
}));

vi.mock("@/lib/audit-log", () => ({ audit: mocks.audit }));

describe("device revocation route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.resolveRequestActor.mockResolvedValue({
      userId: "user-1",
      username: "alice",
    });
    mocks.revokeDevice.mockResolvedValue(true);
    mocks.listDevicesForUser.mockReturnValue([]);
  });

  it("returns 503 instead of an empty list when the device registry is unavailable", async () => {
    mocks.listDevicesForUser.mockImplementation(() => {
      throw new Error("registry unavailable");
    });
    const request = new NextRequest("https://terminalx.example/api/auth/devices");
    const { GET } = await import("@/app/api/auth/devices/route");

    const response = await GET(request);

    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toContain("no-store");
    await expect(response.json()).resolves.toEqual({
      error: "Paired devices are temporarily unavailable. Try again.",
    });
    expect(mocks.audit).toHaveBeenCalledWith("device_registry_read_failed", {
      username: "alice",
      userId: "user-1",
    });
  });

  it("reports success only after durable device revocation", async () => {
    const request = new NextRequest("https://terminalx.example/api/auth/devices?id=device-1", {
      method: "DELETE",
    });
    const { DELETE } = await import("@/app/api/auth/devices/route");

    const response = await DELETE(request);

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(mocks.revokeDevice).toHaveBeenCalledWith("device-1", "user-1");
    expect(mocks.audit).toHaveBeenCalledWith("device_revoked", {
      username: "alice",
      userId: "user-1",
      detail: "device-1",
    });
  });

  it("returns a retryable failure and no success audit when persistence fails", async () => {
    mocks.revokeDevice.mockRejectedValue(new Error("disk unavailable"));
    const request = new NextRequest("https://terminalx.example/api/auth/devices?id=device-1", {
      method: "DELETE",
    });
    const { DELETE } = await import("@/app/api/auth/devices/route");

    const response = await DELETE(request);

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: "Device revocation could not be completed safely. Try again.",
    });
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(mocks.audit).toHaveBeenCalledWith("device_revocation_failed", {
      username: "alice",
      userId: "user-1",
      detail: "device-1",
    });
    expect(mocks.audit).not.toHaveBeenCalledWith("device_revoked", expect.anything());
  });
});
