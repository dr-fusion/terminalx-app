import type {
  PlatformSecurityRuntimeCapability,
  RuntimeCapability,
  RuntimeCommand,
} from "./contracts";

type RuntimeCommandKind = RuntimeCommand["kind"];
type RuntimeCommandCapabilityByKind = {
  readonly [Kind in RuntimeCommandKind]: Extract<
    RuntimeCommand,
    { readonly kind: Kind }
  >["authority"]["capability"];
};

/** The single capability that can authorize each portable Runtime command. */
export const RUNTIME_COMMAND_CAPABILITY = Object.freeze({
  "run.start": "run.start",
  "run.revise": "run.revise",
  "goal-set.apply": "goal-set.apply",
  "run.pause": "run.pause",
  "run.resume": "run.resume",
  "run.stop": "run.stop",
  "run.emergency-stop": "run.emergency-stop",
  "agent.directive": "agent.directive",
  "terminal.input": "terminal.input",
  "terminal.resize": "terminal.resize",
  "process.interrupt": "process.interrupt",
  "action.resolve": "action.resolve",
  "fence.advance": "fence.advance",
  "checkpoint.create": "checkpoint.create",
  "safety.quarantine": "safety.quarantine",
} as const satisfies RuntimeCommandCapabilityByKind);

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

const PLATFORM_SECURITY_CAPABILITIES = new Set<PlatformSecurityRuntimeCapability>([
  "run.emergency-stop",
  "safety.quarantine",
]);

const SAFE_AUTHORITY_REF = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,299}$/;
const SHA256 = /^[0-9a-f]{64}$/;

export class RuntimeAuthorityBindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RuntimeAuthorityBindingError";
  }
}

/**
 * Fail-closed structural check for a deserialized Runtime command boundary.
 * Signature verification and recomputation of `claimsDigest` remain the
 * caller's cryptographic responsibility; this check prevents a valid envelope
 * for one capability from being accepted for a different command kind.
 */
export function assertRuntimeCommandAuthorityBinding(command: unknown): void {
  const record = requirePlainDataRecord(command, "Runtime command");
  const kind = dataField(record, "kind");
  if (typeof kind !== "string" || !Object.hasOwn(RUNTIME_COMMAND_CAPABILITY, kind)) {
    invalid("Runtime command kind is invalid");
  }
  const capability = RUNTIME_COMMAND_CAPABILITY[kind as RuntimeCommandKind];
  assertAuthorityEnvelope(dataField(record, "authority"), capability, true);
}

/** Fail-closed authority check for the separate destructive retire method. */
export function assertRuntimeRetireAuthorityBinding(request: unknown): void {
  const record = requirePlainDataRecord(request, "Runtime retire request");
  assertAuthorityEnvelope(dataField(record, "authority"), "runtime.retire", false);
}

function assertAuthorityEnvelope(
  value: unknown,
  expectedCapability: RuntimeCapability,
  platformSecurityAllowed: boolean
): void {
  const authority = requirePlainDataRecord(value, "Runtime authority");
  const keys = Reflect.ownKeys(authority);
  if (
    keys.length !== AUTHORITY_FIELDS.size ||
    keys.some((key) => typeof key !== "string" || !AUTHORITY_FIELDS.has(key))
  ) {
    invalid("Runtime authority fields are invalid");
  }

  const issuerKeyId = dataField(authority, "issuerKeyId");
  const audience = dataField(authority, "audience");
  const claimsDigest = dataField(authority, "claimsDigest");
  const issuedAtMs = dataField(authority, "issuedAtMs");
  const expiresAtMs = dataField(authority, "expiresAtMs");
  const signature = dataField(authority, "signature");
  const issuer = dataField(authority, "issuer");
  const capability = dataField(authority, "capability");

  if (
    typeof issuerKeyId !== "string" ||
    !SAFE_AUTHORITY_REF.test(issuerKeyId) ||
    audience !== "runtime" ||
    typeof claimsDigest !== "string" ||
    !SHA256.test(claimsDigest) ||
    !isNonNegativeSafeInteger(issuedAtMs) ||
    !isNonNegativeSafeInteger(expiresAtMs) ||
    expiresAtMs <= issuedAtMs ||
    typeof signature !== "string" ||
    signature.length < 1 ||
    signature.length > 4_000 ||
    signature.trim() !== signature ||
    /[\u0000-\u001f\u007f]/.test(signature) ||
    capability !== expectedCapability
  ) {
    invalid("Runtime authority envelope is invalid");
  }

  if (issuer === "team-session" && expectedCapability !== "safety.quarantine") return;
  if (
    issuer === "platform-security" &&
    platformSecurityAllowed &&
    PLATFORM_SECURITY_CAPABILITIES.has(expectedCapability as PlatformSecurityRuntimeCapability)
  ) {
    return;
  }
  invalid("Runtime authority issuer cannot grant this capability");
}

function requirePlainDataRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid(`${label} must be a plain object`);
  }
  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    invalid(`${label} must be inspectable`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    invalid(`${label} must be a plain object`);
  }
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      !descriptor ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      invalid(`${label} contains an invalid field`);
    }
  }
  return value as Record<string, unknown>;
}

function dataField(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
    invalid(`Runtime authority binding is missing ${key}`);
  }
  return descriptor.value;
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function invalid(message: string): never {
  throw new RuntimeAuthorityBindingError(message);
}
