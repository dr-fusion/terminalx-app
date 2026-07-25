import { readFileSync } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hostedRuntimeSelected, legacyTelegramIntegrationEnabled } from "@/lib/telegram/config";

/**
 * Slice 8F completes the re-scoped 8E legacy Telegram retirement decision: a
 * hosted Runtime deployment must never compose the legacy host-global adapter,
 * even when `TERMINALX_LEGACY_TELEGRAM` is on, while the flag continues to back
 * the LocalTmux dev/prod deployment.
 */
describe("legacy Telegram isolation from hosted composition", () => {
  const savedHosted = process.env.TERMINALX_HOSTED_RUNTIME;
  const savedLegacy = process.env.TERMINALX_LEGACY_TELEGRAM;

  beforeEach(() => {
    delete process.env.TERMINALX_HOSTED_RUNTIME;
    delete process.env.TERMINALX_LEGACY_TELEGRAM;
  });

  afterEach(() => {
    restore("TERMINALX_HOSTED_RUNTIME", savedHosted);
    restore("TERMINALX_LEGACY_TELEGRAM", savedLegacy);
  });

  it("keeps the legacy adapter available for LocalTmux by default", () => {
    expect(hostedRuntimeSelected()).toBe(false);
    expect(legacyTelegramIntegrationEnabled()).toBe(true);
  });

  it("honors the disable flag for LocalTmux", () => {
    process.env.TERMINALX_LEGACY_TELEGRAM = "false";
    expect(legacyTelegramIntegrationEnabled()).toBe(false);
  });

  it("disables the legacy adapter under a hosted Runtime even when the flag is on", () => {
    process.env.TERMINALX_HOSTED_RUNTIME = "daytona";
    process.env.TERMINALX_LEGACY_TELEGRAM = "true";
    expect(hostedRuntimeSelected()).toBe(true);
    expect(legacyTelegramIntegrationEnabled()).toBe(false);
  });

  it("treats any non-empty hosted selector as hosted intent", () => {
    process.env.TERMINALX_HOSTED_RUNTIME = "daytona";
    expect(legacyTelegramIntegrationEnabled()).toBe(false);
    process.env.TERMINALX_HOSTED_RUNTIME = "   ";
    expect(hostedRuntimeSelected()).toBe(false);
  });

  it("returns null from the legacy bot startup path under a hosted Runtime with the flag on", async () => {
    process.env.TERMINALX_HOSTED_RUNTIME = "daytona";
    process.env.TERMINALX_LEGACY_TELEGRAM = "true";
    const { startTelegramBot } = await import("@/lib/telegram/bot");
    await expect(startTelegramBot()).resolves.toBeNull();
  });

  it("does not import the legacy Telegram bot from the hosted composition path", () => {
    const root = path.resolve(__dirname, "..", "..");
    const hostedCompositionSources = [
      "server/production-hosted-runtime.ts",
      "src/lib/runtime/hosted-multiplayer-service.ts",
      "src/lib/runtime/hosted-runtime-adapter.ts",
      "src/lib/runtime/runtime-supervisor-composition.ts",
    ];
    for (const relative of hostedCompositionSources) {
      const contents = readFileSync(path.join(root, relative), "utf8");
      expect(contents, `${relative} must not import the legacy Telegram bot`).not.toMatch(
        /lib\/telegram\/bot/
      );
      expect(contents).not.toMatch(/startTelegramBot/);
    }
  });
});

function restore(key: string, value: string | undefined): void {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}
