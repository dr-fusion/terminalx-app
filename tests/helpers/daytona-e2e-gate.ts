import * as fs from "node:fs";
import * as crypto from "node:crypto";
import {
  createPinnedDaytonaFetchApi,
  type DaytonaSandboxApiPort,
  type DaytonaSandboxCreateBody,
} from "@/lib/runtime/daytona-hosted-control-plane";

/**
 * Shared gate + config reader for the real-Daytona E2E harnesses (Phase 12).
 *
 * These harnesses drive a REAL hosted Daytona endpoint. They are OFF by default
 * and SKIP loudly with a logged reason when the environment is absent — they
 * NEVER pass vacuously. When enabled, {@link requireDaytonaE2eConfig} validates
 * that every required value is present and THROWS otherwise, so an
 * enabled-but-half-configured run fails loudly rather than skipping silently.
 *
 * Required environment for a real run:
 *   TERMINALX_DAYTONA_E2E=1                      master switch
 *   TERMINALX_DAYTONA_E2E_ENDPOINT=<https base>  e.g. https://app.daytona.io/api
 *   TERMINALX_DAYTONA_E2E_API_KEY=<token>        or ..._API_KEY_FILE=<path> (preferred)
 *   TERMINALX_DAYTONA_E2E_SNAPSHOT_REF=<ref>     the reviewed sandbox image/snapshot
 *   TERMINALX_DAYTONA_E2E_ORG_ID=<id>            optional (API-key deployments may omit)
 *   TERMINALX_DAYTONA_E2E_TARGET=<region>        optional (default "eu")
 *
 * Deeper in-sandbox command/escape assertions additionally require the full
 * pinned supervisor stack (a signed settings blob) composed via
 * server/production-daytona-hosted-runtime.ts; that is documented in the
 * release-readiness report and is out of scope for the API-port-level harnesses.
 *
 * Secret values are NEVER logged.
 */

export const DAYTONA_E2E_ENV = "TERMINALX_DAYTONA_E2E";

export interface DaytonaE2eConfig {
  readonly endpoint: string;
  readonly organizationId: string | null;
  /** Ownership transfers to each opened API; a fresh copy is minted per open. */
  readonly credentialFactory: () => Uint8Array;
  /**
   * The API credential as a string, used ONLY as the canary the scanner asserts
   * must never appear in any observed surface. Kept in-process for the test only.
   */
  readonly credentialCanary: string;
  readonly snapshotRef: string;
  readonly target: string;
}

function readCredentialBytes(): Uint8Array | null {
  const file = process.env.TERMINALX_DAYTONA_E2E_API_KEY_FILE;
  if (file) {
    const raw = fs.readFileSync(file);
    return new Uint8Array(raw);
  }
  const inline = process.env.TERMINALX_DAYTONA_E2E_API_KEY;
  if (inline) return new Uint8Array(Buffer.from(inline, "utf8"));
  return null;
}

/**
 * Returns a human-readable reason to skip, or null when the harness MUST run.
 * A returned reason is logged by each harness at collection time (loud skip).
 */
export function daytonaE2eSkipReason(): string | null {
  if (process.env[DAYTONA_E2E_ENV] !== "1") {
    return `${DAYTONA_E2E_ENV}!=1 — real hosted-Daytona E2E disabled (no real endpoint in this environment)`;
  }
  const missing: string[] = [];
  if (!process.env.TERMINALX_DAYTONA_E2E_ENDPOINT) missing.push("TERMINALX_DAYTONA_E2E_ENDPOINT");
  if (!process.env.TERMINALX_DAYTONA_E2E_API_KEY && !process.env.TERMINALX_DAYTONA_E2E_API_KEY_FILE)
    missing.push("TERMINALX_DAYTONA_E2E_API_KEY(_FILE)");
  if (!process.env.TERMINALX_DAYTONA_E2E_SNAPSHOT_REF)
    missing.push("TERMINALX_DAYTONA_E2E_SNAPSHOT_REF");
  if (missing.length > 0) {
    return `${DAYTONA_E2E_ENV}=1 but required config is missing: ${missing.join(", ")}`;
  }
  return null;
}

/**
 * Validate and return the config. THROWS (never returns partial) so an enabled
 * run can never pass vacuously — call this in beforeAll of every enabled suite.
 */
export function requireDaytonaE2eConfig(): DaytonaE2eConfig {
  const reason = daytonaE2eSkipReason();
  if (reason !== null) {
    throw new Error(`real-Daytona E2E requested but not runnable: ${reason}`);
  }
  const endpoint = process.env.TERMINALX_DAYTONA_E2E_ENDPOINT as string;
  const snapshotRef = process.env.TERMINALX_DAYTONA_E2E_SNAPSHOT_REF as string;
  const organizationId = process.env.TERMINALX_DAYTONA_E2E_ORG_ID ?? null;
  const target = process.env.TERMINALX_DAYTONA_E2E_TARGET ?? "eu";
  const credentialBytes = readCredentialBytes();
  if (credentialBytes === null || credentialBytes.length === 0) {
    throw new Error("real-Daytona E2E credential is unreadable or empty");
  }
  const credentialCanary = Buffer.from(credentialBytes).toString("utf8").trim();
  return Object.freeze({
    endpoint,
    organizationId,
    snapshotRef,
    target,
    credentialCanary,
    credentialFactory: () => {
      const bytes = readCredentialBytes();
      if (bytes === null || bytes.length === 0) {
        throw new Error("real-Daytona E2E credential is unreadable or empty");
      }
      return bytes;
    },
  });
}

/** Open a pinned Daytona API port. Caller MUST `await api.close()` (zeroes the credential). */
export function openDaytonaApi(config: DaytonaE2eConfig): DaytonaSandboxApiPort {
  return createPinnedDaytonaFetchApi({
    endpoint: config.endpoint,
    organizationId: config.organizationId,
    credential: config.credentialFactory(),
    fetch: globalThis.fetch,
  });
}

/** A single high-entropy seeded canary, minted fresh per test run. */
export function seedCanary(label: string): string {
  return `daytona-e2e/${label}/${crypto.randomBytes(24).toString("hex")}`;
}

/** A short-lived, uniquely labelled sandbox create body for the reviewed snapshot. */
export function e2eCreateBody(
  config: DaytonaE2eConfig,
  labels: Readonly<Record<string, string>>
): DaytonaSandboxCreateBody {
  return Object.freeze({
    name: `terminalx-e2e-${crypto.randomBytes(6).toString("hex")}`,
    snapshot: config.snapshotRef,
    user: "terminalx",
    env: Object.freeze({}),
    labels: Object.freeze({ "terminalx.e2e": "true", ...labels }),
    public: false as const,
    target: config.target,
    cpu: 1,
    memory: 1,
    disk: 2,
    autoStopInterval: 5,
    autoArchiveInterval: 10,
    autoDeleteInterval: 15,
    volumes: [] as const,
    networkBlockAll: true,
  });
}

/** Small helper: an AbortSignal that aborts after `ms` (bounds a hung real call). */
export function timeoutSignal(ms: number): AbortSignal {
  return AbortSignal.timeout(ms);
}
