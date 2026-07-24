// Harness status probe (issue #4, §4).
//
// Produces the data behind Conductor's "Connected" pill + Provider/Plan/Org/
// Account table + "Run <cli> /login" button. Server-only (child_process).
// All probing is best-effort and NEVER throws into the request path; unknown
// fields render as dashes (we do not fabricate account values).

import { execFileSync } from "child_process";
import { isSafeExecutableToken } from "./command";
import { getHarness } from "./registry";

export interface HarnessStatus {
  id: string;
  /** binary resolvable on PATH (or override) */
  installed: boolean;
  /** `command -v` result */
  binPath?: string;
  /** best-effort `<bin> --version` */
  version?: string;
  /** auth present (CLI logged-in OR api-key env set) */
  connected: boolean;
  authMethod: "cli" | "api-key" | "none";
  /** Maps to the Conductor Provider/Plan/Org/Account table; fields are best-effort. */
  account?: {
    provider?: string;
    plan?: string;
    org?: string;
    account?: string;
  };
  /** The login command surfaced by the "Run <cli> /login" button, e.g. "claude /login". */
  loginCommand?: string;
}

/** Resolve the binary, honoring the OpenCode executable-path override. */
function resolveBin(id: string, declared: string | null): string | null {
  if (declared === null) return null;
  if (id === "opencode") {
    const override = process.env.TERMINALX_OPENCODE_BIN;
    if (override && isSafeExecutableToken(override)) return override;
  }
  return isSafeExecutableToken(declared) ? declared : null;
}

/** `command -v <bin>` → absolute path, or undefined when not on PATH. */
function resolveOnPath(bin: string): string | undefined {
  try {
    const out = execFileSync("bash", ["-lc", `command -v ${bin}`], {
      encoding: "utf-8",
      timeout: 2000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return out || undefined;
  } catch {
    return undefined;
  }
}

/** Best-effort `<bin> --version`, time-boxed; returns a trimmed first line. */
function probeVersion(bin: string): string | undefined {
  try {
    const out = execFileSync(bin, ["--version"], {
      encoding: "utf-8",
      timeout: 2000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return out.split("\n")[0]?.trim() || undefined;
  } catch {
    return undefined;
  }
}

// Short-TTL cache so the settings poll and GET /api/harnesses don't shell out
// on every request (probe cost — see spec §10).
const CACHE_TTL_MS = 5000;
const cache = new Map<string, { at: number; value: HarnessStatus }>();

export function probeHarness(id: string): HarnessStatus {
  const cached = cache.get(id);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return cached.value;

  const status = computeStatus(id);
  cache.set(id, { at: Date.now(), value: status });
  return status;
}

/** Clears the probe cache (used by the Refresh affordance / tests). */
export function clearHarnessStatusCache(): void {
  cache.clear();
}

function computeStatus(id: string): HarnessStatus {
  const h = getHarness(id);
  if (!h) {
    return { id, installed: false, connected: false, authMethod: "none" };
  }

  // bash: always installed, no harness-level auth.
  if (h.command.bin === null) {
    return { id, installed: true, connected: true, authMethod: h.auth };
  }

  const bin = resolveBin(id, h.command.bin);
  if (!bin) {
    return { id, installed: false, connected: false, authMethod: h.auth };
  }

  const binPath = resolveOnPath(bin);
  const installed = Boolean(binPath);
  const version = installed ? probeVersion(bin) : undefined;

  // connected / authMethod:
  //  - auth "none" (bash, opencode): connected (auth is per-provider for opencode).
  //  - auth "cli": connected if an API key env is set (api-key method), else we
  //    cannot cheaply confirm a CLI login without invasive shellouts, so we
  //    report not-connected and surface "Run <cli> /login". Never fabricated.
  let connected = false;
  let authMethod: HarnessStatus["authMethod"] = h.auth;
  if (h.auth === "none") {
    connected = true;
  } else if (h.auth === "cli") {
    if (id === "claude" && process.env.ANTHROPIC_API_KEY) {
      connected = true;
      authMethod = "api-key";
    } else {
      authMethod = "cli";
      connected = false;
    }
  }

  const loginCommand = h.auth === "cli" ? `${bin} /login` : undefined;

  return {
    id,
    installed,
    binPath,
    version,
    connected,
    authMethod,
    loginCommand,
    // Account fields are best-effort only; left undefined so the table renders
    // dashes rather than fabricated Provider/Plan/Org/Account values.
    account: undefined,
  };
}
