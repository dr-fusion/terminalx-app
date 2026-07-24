import { constants as fsConstants, closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signEd25519,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import type { RuntimeCommand } from "./contracts";
import { RUNTIME_COMMAND_CAPABILITY } from "./runtime-authority";
import {
  RUNTIME_COMMAND_AUTHORITY_SIGNATURE_DOMAIN,
  canonicalRuntimeJson,
  digestRuntimeCommandClaims,
} from "./runtime-command-canonical";

const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,299}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ED25519_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const DEFAULT_AUTHORITY_TTL_MS = 30_000;
const MAX_AUTHORITY_TTL_MS = 5 * 60_000;
const DEFAULT_MAX_ISSUANCE_DELAY_MS = 5_000;
const MAX_ISSUANCE_DELAY_MS = 60_000;
const MAX_KEY_FILE_BYTES = 64 * 1024;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const AUTHORITY_FIELDS = new Set([
  "issuerKeyId",
  "audience",
  "claimsDigest",
  "issuedAtMs",
  "expiresAtMs",
  "signature",
  "issuer",
  "capability",
]);
const PLATFORM_SECURITY_CAPABILITIES = new Set(["run.emergency-stop", "safety.quarantine"]);

type RuntimeCommandKind = RuntimeCommand["kind"];
type RuntimeCommandByKind = {
  [Kind in RuntimeCommandKind]: Extract<RuntimeCommand, { kind: Kind }>;
};
export type RuntimeAuthorityIssuerName = "team-session" | "platform-security";
export type RuntimeCommandClaims<Kind extends RuntimeCommandKind = RuntimeCommandKind> =
  Kind extends RuntimeCommandKind ? Omit<RuntimeCommandByKind[Kind], "authority"> : never;

export type RuntimeCommandAuthorityErrorCode =
  | "invalid_configuration"
  | "private_key_unavailable"
  | "invalid_private_key"
  | "invalid_public_key"
  | "invalid_command"
  | "invalid_time"
  | "signing_failed";

const SAFE_ERROR_MESSAGES: Readonly<Record<RuntimeCommandAuthorityErrorCode, string>> = {
  invalid_configuration: "Runtime authority configuration is invalid",
  private_key_unavailable: "Runtime authority private key is unavailable",
  invalid_private_key: "Runtime authority private key is invalid",
  invalid_public_key: "Runtime authority public key is invalid",
  invalid_command: "Runtime command cannot be authorized",
  invalid_time: "Runtime authority time window is invalid",
  signing_failed: "Runtime command authority could not be issued",
};

/** Safe failure surface: paths, key bytes, and crypto-library errors are omitted. */
export class RuntimeCommandAuthorityError extends Error {
  constructor(readonly code: RuntimeCommandAuthorityErrorCode) {
    super(SAFE_ERROR_MESSAGES[code]);
    this.name = "RuntimeCommandAuthorityError";
  }
}

export interface CreateRuntimeCommandAuthorityIssuerOptions {
  issuer: RuntimeAuthorityIssuerName;
  issuerKeyId: string;
  /** Absolute, explicit path to a 0400 or 0600 Ed25519 PKCS#8 private-key file. */
  privateKeyFile: string;
  clock?: () => number;
  authorityTtlMs?: number;
  maxIssuanceDelayMs?: number;
}

export interface RuntimeCommandAuthorityIssuer {
  issue<Kind extends RuntimeCommandKind>(
    claims: RuntimeCommandClaims & { readonly kind: Kind }
  ): RuntimeCommandByKind[Kind]["authority"];
}

export interface PinnedRuntimeAuthorityPublicKey {
  issuer: RuntimeAuthorityIssuerName;
  issuerKeyId: string;
  /** An Ed25519 SPKI PEM public key. Private-key PEM is never accepted here. */
  publicKeyPem: string;
}

export interface CreateRuntimeCommandAuthorityVerifierOptions {
  pinnedPublicKeys: readonly PinnedRuntimeAuthorityPublicKey[];
  maximumAuthorityTtlMs?: number;
}

export interface RuntimeCommandAuthorityVerificationInput {
  command: RuntimeCommand;
  nowMs: number;
}

export type RuntimeCommandAuthorityVerifier = (
  input: RuntimeCommandAuthorityVerificationInput
) => boolean;

interface AuthorityStatement {
  version: 1;
  issuer: RuntimeAuthorityIssuerName;
  issuerKeyId: string;
  audience: "runtime";
  capability: string;
  claimsDigest: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

/** Create a process-local issuer whose private key can only originate from a strict file. */
export function createRuntimeCommandAuthorityIssuer(
  options: CreateRuntimeCommandAuthorityIssuerOptions
): RuntimeCommandAuthorityIssuer {
  const issuer = requiredIssuer(options?.issuer);
  const issuerKeyId = requiredKeyId(options?.issuerKeyId);
  const privateKey = loadPrivateKey(options?.privateKeyFile);
  const clock = options.clock ?? Date.now;
  if (typeof clock !== "function") configurationError();
  const authorityTtlMs = boundedInteger(
    options.authorityTtlMs ?? DEFAULT_AUTHORITY_TTL_MS,
    1,
    MAX_AUTHORITY_TTL_MS
  );
  const maxIssuanceDelayMs = boundedInteger(
    options.maxIssuanceDelayMs ?? DEFAULT_MAX_ISSUANCE_DELAY_MS,
    0,
    MAX_ISSUANCE_DELAY_MS
  );

  return Object.freeze({
    issue<Kind extends RuntimeCommandKind>(
      claims: RuntimeCommandClaims & { readonly kind: Kind }
    ): RuntimeCommandByKind[Kind]["authority"] {
      const command = dataRecord(claims, "invalid_command");
      if (Object.hasOwn(command, "authority")) authorityError("invalid_command");
      const capability = commandCapability(command);
      assertIssuerCapability(issuer, capability);
      const commandIssuedAtMs = nonNegativeInteger(
        dataField(command, "issuedAtMs", "invalid_command"),
        "invalid_command"
      );
      const commandDeadlineAtMs = nonNegativeInteger(
        dataField(command, "deadlineAtMs", "invalid_command"),
        "invalid_command"
      );
      if (commandDeadlineAtMs <= commandIssuedAtMs) authorityError("invalid_time");
      const nowMs = sampleClock(clock);
      if (
        nowMs < commandIssuedAtMs ||
        nowMs >= commandDeadlineAtMs ||
        nowMs - commandIssuedAtMs > maxIssuanceDelayMs
      ) {
        authorityError("invalid_time");
      }
      const configuredExpiry = safeAdd(commandIssuedAtMs, authorityTtlMs);
      const expiresAtMs = Math.min(commandDeadlineAtMs, configuredExpiry);
      if (nowMs >= expiresAtMs) authorityError("invalid_time");

      let claimsDigest: string;
      try {
        claimsDigest = digestRuntimeCommandClaims(command);
      } catch {
        authorityError("invalid_command");
      }
      const statement: AuthorityStatement = {
        version: 1,
        issuer,
        issuerKeyId,
        audience: "runtime",
        capability,
        claimsDigest,
        issuedAtMs: commandIssuedAtMs,
        expiresAtMs,
      };
      let signature: string;
      try {
        signature = signEd25519(null, authorityPayload(statement), privateKey).toString(
          "base64url"
        );
      } catch {
        authorityError("signing_failed");
      }
      if (!ED25519_SIGNATURE.test(signature)) authorityError("signing_failed");
      return Object.freeze({
        issuerKeyId,
        audience: "runtime" as const,
        claimsDigest,
        issuedAtMs: commandIssuedAtMs,
        expiresAtMs,
        signature,
        issuer,
        capability,
      }) as RuntimeCommandByKind[Kind]["authority"];
    },
  });
}

/** Create a fail-closed verifier backed only by the supplied immutable key pins. */
export function createRuntimeCommandAuthorityVerifier(
  options: CreateRuntimeCommandAuthorityVerifierOptions
): RuntimeCommandAuthorityVerifier {
  const maximumAuthorityTtlMs = boundedInteger(
    options?.maximumAuthorityTtlMs ?? MAX_AUTHORITY_TTL_MS,
    1,
    MAX_AUTHORITY_TTL_MS
  );
  const publicKeys = loadPinnedPublicKeys(options?.pinnedPublicKeys);

  return Object.freeze((input: RuntimeCommandAuthorityVerificationInput): boolean => {
    try {
      const nowMs = nonNegativeInteger(input?.nowMs, "invalid_time");
      const command = dataRecord(input?.command, "invalid_command");
      const capability = commandCapability(command);
      const authority = exactAuthority(dataField(command, "authority", "invalid_command"));
      const issuer = requiredIssuer(dataField(authority, "issuer", "invalid_command"));
      assertIssuerCapability(issuer, capability);
      const issuerKeyId = requiredKeyId(dataField(authority, "issuerKeyId", "invalid_command"));
      if (
        dataField(authority, "audience", "invalid_command") !== "runtime" ||
        dataField(authority, "capability", "invalid_command") !== capability
      ) {
        return false;
      }
      const commandIssuedAtMs = nonNegativeInteger(
        dataField(command, "issuedAtMs", "invalid_command"),
        "invalid_command"
      );
      const commandDeadlineAtMs = nonNegativeInteger(
        dataField(command, "deadlineAtMs", "invalid_command"),
        "invalid_command"
      );
      const issuedAtMs = nonNegativeInteger(
        dataField(authority, "issuedAtMs", "invalid_command"),
        "invalid_command"
      );
      const expiresAtMs = nonNegativeInteger(
        dataField(authority, "expiresAtMs", "invalid_command"),
        "invalid_command"
      );
      if (
        commandDeadlineAtMs <= commandIssuedAtMs ||
        issuedAtMs !== commandIssuedAtMs ||
        expiresAtMs <= issuedAtMs ||
        expiresAtMs > commandDeadlineAtMs ||
        expiresAtMs - issuedAtMs > maximumAuthorityTtlMs ||
        nowMs < issuedAtMs ||
        nowMs >= expiresAtMs ||
        nowMs >= commandDeadlineAtMs
      ) {
        return false;
      }
      const claimedDigest = dataField(authority, "claimsDigest", "invalid_command");
      if (typeof claimedDigest !== "string" || !SHA256.test(claimedDigest)) return false;
      const actualDigest = digestRuntimeCommandClaims(command);
      if (actualDigest !== claimedDigest) return false;
      const signature = decodeSignature(dataField(authority, "signature", "invalid_command"));
      if (!signature) return false;
      const publicKey = publicKeys.get(pinId(issuer, issuerKeyId));
      if (!publicKey) return false;
      return verifyEd25519(
        null,
        authorityPayload({
          version: 1,
          issuer,
          issuerKeyId,
          audience: "runtime",
          capability,
          claimsDigest: claimedDigest,
          issuedAtMs,
          expiresAtMs,
        }),
        publicKey,
        signature
      );
    } catch {
      return false;
    }
  });
}

function loadPrivateKey(filename: string): KeyObject {
  if (typeof filename !== "string" || !isAbsolute(filename)) {
    authorityError("private_key_unavailable");
  }
  const noFollow = fsConstants.O_NOFOLLOW;
  if (typeof noFollow !== "number" || typeof process.geteuid !== "function") {
    authorityError("private_key_unavailable");
  }
  let descriptor: number;
  try {
    descriptor = openSync(filename, fsConstants.O_RDONLY | noFollow);
  } catch {
    authorityError("private_key_unavailable");
  }
  let bytes: Buffer | undefined;
  try {
    const stat = fstatSync(descriptor);
    const mode = stat.mode & 0o777;
    if (
      !stat.isFile() ||
      stat.uid !== process.geteuid() ||
      stat.nlink !== 1 ||
      (mode !== 0o400 && mode !== 0o600) ||
      (stat.mode & 0o7000) !== 0 ||
      stat.size < 1 ||
      stat.size > MAX_KEY_FILE_BYTES
    ) {
      authorityError("private_key_unavailable");
    }
    bytes = readFileSync(descriptor);
  } catch (error) {
    if (error instanceof RuntimeCommandAuthorityError) throw error;
    authorityError("private_key_unavailable");
  } finally {
    try {
      closeSync(descriptor);
    } catch {
      authorityError("private_key_unavailable");
    }
  }
  try {
    const key = createPrivateKey(bytes);
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
      authorityError("invalid_private_key");
    }
    return key;
  } catch (error) {
    if (error instanceof RuntimeCommandAuthorityError) throw error;
    authorityError("invalid_private_key");
  } finally {
    bytes.fill(0);
  }
}

function loadPinnedPublicKeys(
  pins: readonly PinnedRuntimeAuthorityPublicKey[] | undefined
): ReadonlyMap<string, KeyObject> {
  if (!Array.isArray(pins) || pins.length < 1 || pins.length > 64) {
    authorityError("invalid_public_key");
  }
  const result = new Map<string, KeyObject>();
  const fingerprintIssuers = new Map<string, RuntimeAuthorityIssuerName>();
  for (const pin of pins) {
    const record = dataRecord(pin, "invalid_public_key");
    const issuer = requiredIssuer(dataField(record, "issuer", "invalid_public_key"));
    const issuerKeyId = requiredKeyId(dataField(record, "issuerKeyId", "invalid_public_key"));
    const publicKeyPem = dataField(record, "publicKeyPem", "invalid_public_key");
    if (
      typeof publicKeyPem !== "string" ||
      Buffer.byteLength(publicKeyPem, "utf8") > MAX_PUBLIC_KEY_BYTES ||
      !publicKeyPem.trim().startsWith("-----BEGIN PUBLIC KEY-----") ||
      !publicKeyPem.trim().endsWith("-----END PUBLIC KEY-----") ||
      publicKeyPem.includes("PRIVATE KEY")
    ) {
      authorityError("invalid_public_key");
    }
    const id = pinId(issuer, issuerKeyId);
    if (result.has(id)) authorityError("invalid_public_key");
    let key: KeyObject;
    try {
      key = createPublicKey(publicKeyPem);
    } catch {
      authorityError("invalid_public_key");
    }
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
      authorityError("invalid_public_key");
    }
    let fingerprint: string;
    try {
      fingerprint = createHash("sha256")
        .update(key.export({ type: "spki", format: "der" }))
        .digest("hex");
    } catch {
      authorityError("invalid_public_key");
    }
    const fingerprintIssuer = fingerprintIssuers.get(fingerprint);
    if (fingerprintIssuer !== undefined && fingerprintIssuer !== issuer) {
      authorityError("invalid_public_key");
    }
    fingerprintIssuers.set(fingerprint, issuer);
    result.set(id, key);
  }
  return result;
}

function exactAuthority(value: unknown): Record<string, unknown> {
  const authority = dataRecord(value, "invalid_command");
  const keys = Reflect.ownKeys(authority);
  if (
    keys.length !== AUTHORITY_FIELDS.size ||
    keys.some((key) => typeof key !== "string" || !AUTHORITY_FIELDS.has(key))
  ) {
    authorityError("invalid_command");
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(authority, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      authorityError("invalid_command");
    }
  }
  return authority;
}

function commandCapability(command: Record<string, unknown>): string {
  const kind = dataField(command, "kind", "invalid_command");
  if (typeof kind !== "string" || !Object.hasOwn(RUNTIME_COMMAND_CAPABILITY, kind)) {
    authorityError("invalid_command");
  }
  return RUNTIME_COMMAND_CAPABILITY[kind as RuntimeCommandKind];
}

function assertIssuerCapability(issuer: RuntimeAuthorityIssuerName, capability: string): void {
  if (capability === "safety.quarantine" && issuer !== "platform-security") {
    authorityError("invalid_command");
  }
  if (issuer === "platform-security" && !PLATFORM_SECURITY_CAPABILITIES.has(capability)) {
    authorityError("invalid_command");
  }
}

function authorityPayload(statement: AuthorityStatement): Buffer {
  return Buffer.concat([
    Buffer.from(RUNTIME_COMMAND_AUTHORITY_SIGNATURE_DOMAIN, "utf8"),
    Buffer.from(canonicalRuntimeJson(statement), "utf8"),
  ]);
}

function decodeSignature(value: unknown): Buffer | null {
  if (typeof value !== "string" || !ED25519_SIGNATURE.test(value)) return null;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length === 64 && decoded.toString("base64url") === value ? decoded : null;
  } catch {
    return null;
  }
}

function dataRecord(
  value: unknown,
  code: RuntimeCommandAuthorityErrorCode
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) authorityError(code);
  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    authorityError(code);
  }
  if (prototype !== Object.prototype && prototype !== null) authorityError(code);
  return value as Record<string, unknown>;
}

function dataField(
  record: Record<string, unknown>,
  key: string,
  code: RuntimeCommandAuthorityErrorCode
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) authorityError(code);
  return descriptor.value;
}

function requiredIssuer(value: unknown): RuntimeAuthorityIssuerName {
  if (value !== "team-session" && value !== "platform-security") {
    authorityError("invalid_configuration");
  }
  return value;
}

function requiredKeyId(value: unknown): string {
  if (typeof value !== "string" || !SAFE_KEY_ID.test(value)) {
    authorityError("invalid_configuration");
  }
  return value;
}

function nonNegativeInteger(value: unknown, code: RuntimeCommandAuthorityErrorCode): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) authorityError(code);
  return value as number;
}

function boundedInteger(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    configurationError();
  }
  return value as number;
}

function safeAdd(left: number, right: number): number {
  const value = left + right;
  if (!Number.isSafeInteger(value)) authorityError("invalid_time");
  return value;
}

function sampleClock(clock: () => number): number {
  try {
    return nonNegativeInteger(clock(), "invalid_time");
  } catch (error) {
    if (error instanceof RuntimeCommandAuthorityError) throw error;
    authorityError("invalid_time");
  }
}

function pinId(issuer: RuntimeAuthorityIssuerName, issuerKeyId: string): string {
  return `${issuer}\0${issuerKeyId}`;
}

function configurationError(): never {
  throw new RuntimeCommandAuthorityError("invalid_configuration");
}

function authorityError(code: RuntimeCommandAuthorityErrorCode): never {
  throw new RuntimeCommandAuthorityError(code);
}
