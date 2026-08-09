import { afterEach, describe, expect, it } from "vitest";
import {
  getMultiplayerTransportStatus,
  isMultiplayerTransportAvailable,
  isMultiplayerTransportEnabled,
  markMultiplayerTransportAvailable,
} from "@/lib/team-sessions/feature";
import { GET } from "@/app/api/team-sessions/status/route";

afterEach(() => {
  markMultiplayerTransportAvailable(false);
});

describe("multiplayer feature status", () => {
  it("keeps the trusted-host transport opt-in with strict flag parsing", () => {
    expect(isMultiplayerTransportEnabled(undefined)).toBe(false);
    expect(isMultiplayerTransportEnabled("")).toBe(false);
    expect(isMultiplayerTransportEnabled("false")).toBe(false);
    expect(isMultiplayerTransportEnabled("true")).toBe(true);
    expect(() => isMultiplayerTransportEnabled("TRUE")).toThrow(
      "TERMINALX_MULTIPLAYER_ENABLED must be true or false"
    );
  });

  it("reports actual custom-server ownership rather than configuration alone", async () => {
    expect(isMultiplayerTransportAvailable()).toBe(false);
    let response = await GET();
    await expect(response.json()).resolves.toMatchObject({
      enabled: false,
      runtime: null,
    });
    expect(response.headers.get("cache-control")).toBe("no-store");

    markMultiplayerTransportAvailable(true, {
      kind: "local-tmux",
      isolation: "trusted-shared-host",
      yoloEligible: false,
    });
    expect(isMultiplayerTransportAvailable()).toBe(true);
    response = await GET();
    await expect(response.json()).resolves.toEqual({
      enabled: true,
      runtime: {
        kind: "local-tmux",
        isolation: "trusted-shared-host",
        yoloEligible: false,
      },
    });
  });

  it("reports hosted isolation truth even while admission is withdrawn", async () => {
    const hosted = {
      kind: "daytona" as const,
      isolation: "isolated-hosted" as const,
      yoloEligible: false as const,
    };
    markMultiplayerTransportAvailable(true, hosted);
    expect(getMultiplayerTransportStatus()).toEqual({ enabled: true, runtime: hosted });

    markMultiplayerTransportAvailable(false, hosted);
    const response = await GET();
    await expect(response.json()).resolves.toEqual({ enabled: false, runtime: hosted });
  });

  it("rejects available or mismatched Runtime status instead of inventing LocalTmux", () => {
    expect(() => markMultiplayerTransportAvailable(true)).toThrow(
      "Available multiplayer transport requires a Runtime profile"
    );
    expect(() =>
      markMultiplayerTransportAvailable(true, {
        kind: "daytona",
        isolation: "trusted-shared-host",
        yoloEligible: false,
      } as never)
    ).toThrow("Multiplayer Runtime profile is invalid");
    expect(isMultiplayerTransportAvailable()).toBe(false);
  });
});
