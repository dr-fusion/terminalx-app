import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("Daytona daemon PTY driver production contract", () => {
  it("uses only the inherited root-only Unix listener and requests the fixed sanitized shell", () => {
    const source = readFileSync(
      join(process.cwd(), "packages/daytona-supervisor/src/daytona-daemon-pty-driver.ts"),
      "utf8"
    );
    expect(source).toContain(
      'const FIXED_DAEMON_SOCKET = "/run/terminalx-private/daytona-daemon.sock" as const;'
    );
    expect(source).toContain("socketPath: FIXED_DAEMON_SOCKET");
    expect(source).toContain("`ws+unix://${FIXED_DAEMON_SOCKET}:/process/pty/");
    expect(source).toContain("sanitizeEnv: true");
    expect(source).toContain('const FIXED_WORKING_DIRECTORY = "/home/terminalx" as const;');
    expect(source).not.toContain("127.0.0.1");
    expect(source).not.toContain("2280");
    expect(source).not.toContain("os.Environ");
  });
});
