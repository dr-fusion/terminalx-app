import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
} from "node:crypto";
import { types as nodeTypes } from "node:util";
import type {
  HostedRuntimeObservationProvisioningRequest,
  HostedRuntimeObservationRegistration,
} from "../team-sessions/module";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type {
  DaytonaAssignmentBootstrapInstallRequest,
  DaytonaAssignmentBootstrapPrivateKeys,
} from "./daytona-assignment-bootstrap-saga";
import type { HostedRuntimeAssignmentPlan } from "./hosted-runtime-control-plane";
import { HostedControlPlaneError } from "./hosted-runtime-control-plane";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import {
  exactRuntimeSupervisorDataRecord,
  runtimeSupervisorDataField,
  snapshotRuntimeSupervisorPortableData,
} from "./runtime-supervisor-snapshot";

export const DAYTONA_ASSIGNMENT_KEY_CONTEXT_DIGEST_DOMAIN =
  "terminalx/daytona-assignment-key-context/v1\0" as const;
export const DAYTONA_OBSERVATION_KEY_SEED_DOMAIN =
  "terminalx/daytona-observation-ed25519-seed/v1\0" as const;
export const DAYTONA_EFFECT_ENFORCER_KEY_SEED_DOMAIN =
  "terminalx/daytona-effect-enforcer-ed25519-seed/v1\0" as const;

const MASTER_KEY_BYTES = 32;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;
const INCARNATION = SHA256;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SAFE_MASTER_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/;
const ED25519_PKCS8_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export interface CreateDaytonaAssignmentKeyRegistryOptions {
  /** Stable non-secret identifier for rotation and operational diagnosis. */
  readonly masterKeyId: string;
  /**
   * Exactly 32 root-private bytes loaded before SQLite opens. Ownership
   * transfers to the registry and the caller's view is zeroed on every path.
   */
  readonly masterKey: Uint8Array;
}

export interface DaytonaAssignmentEffectEnforcerIdentity {
  readonly enforcerRef: string;
  readonly enforcerKeyId: string;
  readonly publicKeySpkiPem: string;
  readonly publicKeySpkiDigest: string;
}

/**
 * Synchronous, deterministic assignment key derivation. None of these methods
 * performs filesystem, vault, network, provider, or database I/O.
 */
export interface DaytonaAssignmentKeyRegistry {
  provisionObservation(
    request: HostedRuntimeObservationProvisioningRequest
  ): HostedRuntimeObservationRegistration;
  resolvePrivateKeys(
    request: DaytonaAssignmentBootstrapInstallRequest
  ): DaytonaAssignmentBootstrapPrivateKeys;
  effectEnforcerIdentity(
    plan: HostedRuntimeAssignmentPlan
  ): DaytonaAssignmentEffectEnforcerIdentity;
  /** Idempotently zero the captured master key. */
  close(): void;
}

interface AssignmentKeyContext {
  readonly version: 1;
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly incarnation: string;
  readonly adapterConfigurationRef: string;
}

interface SnapshotPlanContext {
  readonly context: AssignmentKeyContext;
  readonly observation: HostedRuntimeAssignmentPlan["observation"];
}

interface DerivedKey {
  readonly privateKeyPkcs8Der: Buffer;
  readonly publicKeySpkiPem: string;
  readonly publicKeySpkiDigest: string;
}

interface CapturedRegistryOptions {
  readonly masterKeyId: string;
  readonly masterKey: Buffer;
}

export function createDaytonaAssignmentKeyRegistry(
  unsafeOptions: CreateDaytonaAssignmentKeyRegistryOptions
): DaytonaAssignmentKeyRegistry {
  const options = captureOptions(unsafeOptions);
  let closed = false;

  const assertOpen = (): void => {
    if (closed) unavailable();
  };

  const provisionObservation = (
    unsafeRequest: HostedRuntimeObservationProvisioningRequest
  ): HostedRuntimeObservationRegistration => {
    assertOpen();
    const context = snapshotProvisioningRequest(unsafeRequest);
    const contextDigest = digestContext(context);
    const derived = deriveKey(options.masterKey, DAYTONA_OBSERVATION_KEY_SEED_DOMAIN, context);
    try {
      return observationRegistration(options.masterKeyId, contextDigest, derived);
    } finally {
      derived.privateKeyPkcs8Der.fill(0);
    }
  };

  const resolvePrivateKeys = (
    unsafeRequest: DaytonaAssignmentBootstrapInstallRequest
  ): DaytonaAssignmentBootstrapPrivateKeys => {
    assertOpen();
    const plan = snapshotInstallRequest(unsafeRequest);
    const contextDigest = digestContext(plan.context);
    const observation = deriveKey(
      options.masterKey,
      DAYTONA_OBSERVATION_KEY_SEED_DOMAIN,
      plan.context
    );
    let effect: DerivedKey | undefined;
    try {
      const expected = observationRegistration(options.masterKeyId, contextDigest, observation);
      assertObservationMatches(plan.observation, expected);
      effect = deriveKey(options.masterKey, DAYTONA_EFFECT_ENFORCER_KEY_SEED_DOMAIN, plan.context);
      if (sameBytes(observation.privateKeyPkcs8Der, effect.privateKeyPkcs8Der)) invalidState();
      return Object.freeze({
        observationPrivateKeyPkcs8Der: observation.privateKeyPkcs8Der,
        effectEnforcerPrivateKeyPkcs8Der: effect.privateKeyPkcs8Der,
      });
    } catch (error) {
      observation.privateKeyPkcs8Der.fill(0);
      effect?.privateKeyPkcs8Der.fill(0);
      throw error;
    }
  };

  const effectEnforcerIdentity = (
    unsafePlan: HostedRuntimeAssignmentPlan
  ): DaytonaAssignmentEffectEnforcerIdentity => {
    assertOpen();
    const plan = snapshotPlanContext(unsafePlan);
    const contextDigest = digestContext(plan.context);
    const observation = deriveKey(
      options.masterKey,
      DAYTONA_OBSERVATION_KEY_SEED_DOMAIN,
      plan.context
    );
    try {
      assertObservationMatches(
        plan.observation,
        observationRegistration(options.masterKeyId, contextDigest, observation)
      );
    } finally {
      observation.privateKeyPkcs8Der.fill(0);
    }
    const effect = deriveKey(
      options.masterKey,
      DAYTONA_EFFECT_ENFORCER_KEY_SEED_DOMAIN,
      plan.context
    );
    try {
      return Object.freeze({
        enforcerRef: `daytona-runtime-enforcer:v1:${options.masterKeyId}:${contextDigest}`,
        enforcerKeyId: `daytona-effect-enforcer:v1:${options.masterKeyId}:${contextDigest}`,
        publicKeySpkiPem: effect.publicKeySpkiPem,
        publicKeySpkiDigest: effect.publicKeySpkiDigest,
      });
    } finally {
      effect.privateKeyPkcs8Der.fill(0);
    }
  };

  const close = (): void => {
    if (closed) return;
    closed = true;
    options.masterKey.fill(0);
  };

  return Object.freeze({
    provisionObservation,
    resolvePrivateKeys,
    effectEnforcerIdentity,
    close,
  });
}

function captureOptions(value: unknown): CapturedRegistryOptions {
  let sourceMasterKey: unknown;
  try {
    if (typeof value === "object" && value !== null && !nodeTypes.isProxy(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, "masterKey");
      if (descriptor && "value" in descriptor) sourceMasterKey = descriptor.value;
    }
    const record = exactOptionsRecord(value, ["masterKeyId", "masterKey"]);
    const masterKeyId = optionsField(record, "masterKeyId");
    sourceMasterKey = optionsField(record, "masterKey");
    if (
      typeof masterKeyId !== "string" ||
      !SAFE_MASTER_KEY_ID.test(masterKeyId) ||
      !isOwnedMasterKey(sourceMasterKey)
    ) {
      invalidState();
    }
    return Object.freeze({
      masterKeyId,
      masterKey: Buffer.from(sourceMasterKey),
    });
  } catch (error) {
    if (error instanceof HostedControlPlaneError) throw error;
    invalidState();
  } finally {
    zeroSourceMasterKey(sourceMasterKey);
  }
}

function snapshotProvisioningRequest(value: unknown): AssignmentKeyContext {
  try {
    const snapshot = snapshotRuntimeSupervisorPortableData(value);
    const record = exactRuntimeSupervisorDataRecord(snapshot, [
      "binding",
      "runtimeAuthorizationGeneration",
      "incarnation",
      "adapterConfigurationRef",
    ]);
    return freezeContext({
      binding: snapshotBinding(field(record, "binding")),
      runtimeAuthorizationGeneration: positiveInteger(
        field(record, "runtimeAuthorizationGeneration")
      ),
      incarnation: incarnation(field(record, "incarnation")),
      adapterConfigurationRef: safeReference(field(record, "adapterConfigurationRef")),
    });
  } catch (error) {
    if (error instanceof HostedControlPlaneError) throw error;
    invalidState();
  }
}

function snapshotInstallRequest(value: unknown): SnapshotPlanContext {
  try {
    const snapshot = snapshotRuntimeSupervisorPortableData(value);
    const record = exactRuntimeSupervisorDataRecord(snapshot, [
      "providerSandboxId",
      "plan",
      "expectedRevision",
      "artifactDigest",
      "sandboxUser",
      "supervisorArtifactDigest",
      "runnerBinaryDigest",
    ]);
    const providerSandboxId = field(record, "providerSandboxId");
    if (
      typeof providerSandboxId !== "string" ||
      !UUID_V4.test(providerSandboxId) ||
      field(record, "sandboxUser") !== "terminalx"
    ) {
      invalidState();
    }
    positiveInteger(field(record, "expectedRevision"));
    digest(field(record, "artifactDigest"));
    digest(field(record, "supervisorArtifactDigest"));
    digest(field(record, "runnerBinaryDigest"));
    return snapshotPlanContext(field(record, "plan"));
  } catch (error) {
    if (error instanceof HostedControlPlaneError) throw error;
    invalidState();
  }
}

function snapshotPlanContext(value: unknown): SnapshotPlanContext {
  try {
    const snapshot = snapshotRuntimeSupervisorPortableData(value);
    const record = exactRuntimeSupervisorDataRecord(snapshot, [
      "binding",
      "runtimeAuthorizationGeneration",
      "incarnation",
      "specificationDigest",
      "effectEnforcerPolicyDigest",
      "adapterConfigurationRef",
      "observation",
      "isolation",
      "capabilities",
    ]);
    digest(field(record, "specificationDigest"));
    digest(field(record, "effectEnforcerPolicyDigest"));
    // The complete plan remains an input to canonical assignment digests. This
    // check rejects non-portable data even though key derivation deliberately
    // depends only on the immutable identity context below.
    canonicalRuntimeJson(snapshot);
    return Object.freeze({
      context: freezeContext({
        binding: snapshotBinding(field(record, "binding")),
        runtimeAuthorizationGeneration: positiveInteger(
          field(record, "runtimeAuthorizationGeneration")
        ),
        incarnation: incarnation(field(record, "incarnation")),
        adapterConfigurationRef: safeReference(field(record, "adapterConfigurationRef")),
      }),
      observation: snapshotObservation(field(record, "observation")),
    });
  } catch (error) {
    if (error instanceof HostedControlPlaneError) throw error;
    invalidState();
  }
}

function freezeContext(value: Omit<AssignmentKeyContext, "version">): AssignmentKeyContext {
  return Object.freeze({ version: 1, ...value });
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const record = exactRuntimeSupervisorDataRecord(value, [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "runtimeAssignmentGeneration",
    "sandboxId",
    "sandboxGeneration",
    "runtimePrincipalId",
  ]);
  return Object.freeze({
    teamId: safeReference(field(record, "teamId")),
    projectId: safeReference(field(record, "projectId")),
    sessionId: safeReference(field(record, "sessionId")),
    runtimeAssignmentId: safeReference(field(record, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(field(record, "runtimeAssignmentGeneration")),
    sandboxId: safeReference(field(record, "sandboxId")),
    sandboxGeneration: positiveInteger(field(record, "sandboxGeneration")),
    runtimePrincipalId: safeReference(field(record, "runtimePrincipalId")),
  });
}

function snapshotObservation(value: unknown): HostedRuntimeAssignmentPlan["observation"] {
  const record = exactRuntimeSupervisorDataRecord(value, [
    "keyProvisioningRef",
    "issuerKeyId",
    "publicKeySpkiPem",
  ]);
  const publicKeySpkiPem = field(record, "publicKeySpkiPem");
  if (
    typeof publicKeySpkiPem !== "string" ||
    Buffer.byteLength(publicKeySpkiPem, "utf8") > MAX_PUBLIC_KEY_BYTES ||
    !isCanonicalEd25519PublicKey(publicKeySpkiPem)
  ) {
    invalidState();
  }
  return Object.freeze({
    keyProvisioningRef: safeReference(field(record, "keyProvisioningRef")),
    issuerKeyId: safeReference(field(record, "issuerKeyId")),
    publicKeySpkiPem,
  });
}

function observationRegistration(
  masterKeyId: string,
  contextDigest: string,
  derived: DerivedKey
): HostedRuntimeObservationRegistration {
  return Object.freeze({
    keyProvisioningRef: `daytona-assignment-key:v1:${masterKeyId}:${contextDigest}`,
    issuerKeyId: `daytona-observation:v1:${masterKeyId}:${contextDigest}`,
    publicKeySpkiPem: derived.publicKeySpkiPem,
  });
}

function assertObservationMatches(
  actual: HostedRuntimeAssignmentPlan["observation"],
  expected: HostedRuntimeObservationRegistration
): void {
  if (
    actual.keyProvisioningRef !== expected.keyProvisioningRef ||
    actual.issuerKeyId !== expected.issuerKeyId ||
    actual.publicKeySpkiPem !== expected.publicKeySpkiPem
  ) {
    conflict();
  }
}

function digestContext(context: AssignmentKeyContext): string {
  return createHash("sha256")
    .update(DAYTONA_ASSIGNMENT_KEY_CONTEXT_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson(context), "utf8")
    .digest("hex");
}

function deriveKey(
  masterKey: Buffer,
  domain:
    | typeof DAYTONA_OBSERVATION_KEY_SEED_DOMAIN
    | typeof DAYTONA_EFFECT_ENFORCER_KEY_SEED_DOMAIN,
  context: AssignmentKeyContext
): DerivedKey {
  const seed = createHmac("sha256", masterKey)
    .update(domain, "utf8")
    .update(canonicalRuntimeJson(context), "utf8")
    .digest();
  const candidate = Buffer.allocUnsafe(ED25519_PKCS8_SEED_PREFIX.byteLength + seed.byteLength);
  ED25519_PKCS8_SEED_PREFIX.copy(candidate, 0);
  seed.copy(candidate, ED25519_PKCS8_SEED_PREFIX.byteLength);
  let privateKeyPkcs8Der: Buffer | undefined;
  try {
    const privateKey = createPrivateKey({ key: candidate, format: "der", type: "pkcs8" });
    if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
      invalidState();
    }
    const exported = privateKey.export({ format: "der", type: "pkcs8" });
    if (!Buffer.isBuffer(exported)) invalidState();
    privateKeyPkcs8Der = Buffer.from(exported);
    exported.fill(0);
    const publicKey = createPublicKey(privateKey);
    const publicKeySpkiPem = String(publicKey.export({ format: "pem", type: "spki" }));
    const publicKeySpkiDer = publicKey.export({ format: "der", type: "spki" });
    if (!Buffer.isBuffer(publicKeySpkiDer)) invalidState();
    const publicKeySpkiDigest = createHash("sha256").update(publicKeySpkiDer).digest("hex");
    return Object.freeze({
      privateKeyPkcs8Der,
      publicKeySpkiPem,
      publicKeySpkiDigest,
    });
  } catch (error) {
    privateKeyPkcs8Der?.fill(0);
    if (error instanceof HostedControlPlaneError) throw error;
    invalidState();
  } finally {
    candidate.fill(0);
    seed.fill(0);
  }
}

function exactOptionsRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    invalidState();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    invalidState();
  }
  for (const name of fields) optionsField(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function optionsField(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalidState();
  return descriptor.value;
}

function isOwnedMasterKey(value: unknown): value is Uint8Array {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Uint8Array.prototype && prototype !== Buffer.prototype) return false;
  if (!(value instanceof Uint8Array) || value.byteLength !== MASTER_KEY_BYTES) return false;
  return value.buffer instanceof ArrayBuffer;
}

function zeroSourceMasterKey(value: unknown): void {
  if (!isOwnedMasterKey(value)) return;
  try {
    Uint8Array.prototype.fill.call(value, 0);
  } catch {
    // A concurrently detached caller-owned view is already unusable. Never
    // replace the primary safe configuration error with a cleanup exception.
  }
}

function isCanonicalEd25519PublicKey(value: string): boolean {
  if (
    !value.startsWith("-----BEGIN PUBLIC KEY-----\n") ||
    !value.endsWith("-----END PUBLIC KEY-----\n") ||
    value.includes("PRIVATE KEY")
  ) {
    return false;
  }
  try {
    const key = createPublicKey(value);
    return (
      key.type === "public" &&
      key.asymmetricKeyType === "ed25519" &&
      String(key.export({ format: "pem", type: "spki" })) === value
    );
  } catch {
    return false;
  }
}

function field(record: Record<string, unknown>, name: string): unknown {
  return runtimeSupervisorDataField(record, name);
}

function safeReference(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 300 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    invalidState();
  }
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) invalidState();
  return value as number;
}

function incarnation(value: unknown): string {
  if (typeof value !== "string" || !INCARNATION.test(value)) invalidState();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) invalidState();
  return value;
}

function sameBytes(left: Buffer, right: Buffer): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

function invalidState(): never {
  throw new HostedControlPlaneError("invalid-state");
}

function conflict(): never {
  throw new HostedControlPlaneError("conflict");
}

function unavailable(): never {
  throw new HostedControlPlaneError("unavailable");
}
