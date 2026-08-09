import { createPrivateKey, createPublicKey, timingSafeEqual } from "node:crypto";
import { types as nodeTypes } from "node:util";
import type { RuntimeBinding } from "../../../src/lib/team-sessions/contracts";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import {
  createRuntimeCompensationReceiptObservationIssuer,
  type RuntimeCompensationReceiptObservationIssueInput,
  type RuntimeCompensationReceiptObservationIssuer,
} from "../../../src/lib/runtime/runtime-compensation-receipt-observation";
import {
  createRuntimeReceiptObservationIssuer,
  type RuntimeReceiptObservationIssueInput,
  type RuntimeReceiptObservationIssuer,
} from "../../../src/lib/runtime/runtime-receipt-observation";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import { readTrustedConfigurationFile } from "../../../src/lib/runtime/runtime-trusted-configuration-file";
import { DaytonaSupervisorProtocolError } from "./supervisor";

const PROVISIONING_RECORD_KIND = "terminalx.daytona-observation-key-provisioning" as const;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/u;
const MAX_RECORD_BYTES = 64 * 1024;
const MAX_PRIVATE_KEY_BYTES = 64 * 1024;

export interface DaytonaSupervisorObservationCredentialRequest {
  readonly keyProvisioningRef: string;
  readonly binding: RuntimeBinding;
  readonly issuerKeyId: string;
  readonly publicKeySpkiPem: string;
}

/** Contains signing capabilities, never raw private bytes or a provider identifier. */
export interface DaytonaSupervisorObservationIssuerLease {
  readonly lifecycleObservationIssuer: RuntimeReceiptObservationIssuer;
  readonly compensationObservationIssuer: RuntimeCompensationReceiptObservationIssuer;
  close(): Promise<void>;
}

export interface DaytonaSupervisorObservationCredentialResolver {
  resolve(
    request: DaytonaSupervisorObservationCredentialRequest,
    signal: AbortSignal
  ): Promise<DaytonaSupervisorObservationIssuerLease>;
}

export interface CreateRootFileObservationCredentialResolverOptions {
  /** Root-owned 0500/0700 directory inaccessible to the Daytona daemon/agent uid. */
  readonly trustedConfigurationRoot: string;
  /** Root-owned provisioning record for exactly one assignment. */
  readonly provisioningRecordFile: string;
  readonly observationTtlMs?: number;
  readonly clock?: () => number;
}

/**
 * Resolve one opaque plan reference inside the distinct uid-0 supervisor. This
 * must not be constructed in the b5 toolbox/agent process, whose uid boundary
 * is insufficient.
 */
export function createRootFileObservationCredentialResolver(
  unsafeOptions: CreateRootFileObservationCredentialResolverOptions
): DaytonaSupervisorObservationCredentialResolver {
  if (
    typeof process.geteuid !== "function" ||
    process.geteuid() !== 0 ||
    typeof unsafeOptions !== "object" ||
    unsafeOptions === null ||
    nodeTypes.isProxy(unsafeOptions)
  ) {
    throw new DaytonaSupervisorProtocolError("not-ready");
  }
  const trustedConfigurationRoot = unsafeOptions.trustedConfigurationRoot;
  const provisioningRecordFile = unsafeOptions.provisioningRecordFile;
  const observationTtlMs = unsafeOptions.observationTtlMs;
  const clock = unsafeOptions.clock;

  return Object.freeze({
    async resolve(
      unsafeRequest: DaytonaSupervisorObservationCredentialRequest,
      signal: AbortSignal
    ): Promise<DaytonaSupervisorObservationIssuerLease> {
      assertNotAborted(signal);
      try {
        const request = snapshotRequest(unsafeRequest);
        const recordBytes = readTrustedConfigurationFile({
          trustedConfigurationRoot,
          filePath: provisioningRecordFile,
          minimumBytes: 2,
          maximumBytes: MAX_RECORD_BYTES,
        });
        let record: ProvisioningRecord;
        try {
          record = snapshotProvisioningRecord(JSON.parse(recordBytes.toString("utf8")));
        } finally {
          recordBytes.fill(0);
        }
        if (
          record.keyProvisioningRef !== request.keyProvisioningRef ||
          record.issuerKeyId !== request.issuerKeyId ||
          canonicalRuntimeJson(record.binding) !== canonicalRuntimeJson(request.binding) ||
          record.publicKeySpkiPem !== request.publicKeySpkiPem
        ) {
          throw new TypeError();
        }
        assertPrivateKeyMatchesPublic(
          trustedConfigurationRoot,
          record.privateKeyFile,
          record.publicKeySpkiPem
        );
        assertNotAborted(signal);
        const lifecycle = createRuntimeReceiptObservationIssuer({
          issuerKeyId: record.issuerKeyId,
          binding: record.binding,
          trustedConfigurationRoot,
          privateKeyFile: record.privateKeyFile,
          ...(clock === undefined ? {} : { clock }),
          ...(observationTtlMs === undefined ? {} : { observationTtlMs }),
        });
        const compensation = createRuntimeCompensationReceiptObservationIssuer({
          issuerKeyId: record.issuerKeyId,
          binding: record.binding,
          trustedConfigurationRoot,
          privateKeyFile: record.privateKeyFile,
          ...(clock === undefined ? {} : { clock }),
          ...(observationTtlMs === undefined ? {} : { observationTtlMs }),
        });
        let active = true;
        return Object.freeze({
          lifecycleObservationIssuer: Object.freeze({
            issue(input: RuntimeReceiptObservationIssueInput) {
              if (!active) throw new DaytonaSupervisorProtocolError("unavailable");
              return lifecycle.issue(input);
            },
          }),
          compensationObservationIssuer: Object.freeze({
            issue(input: RuntimeCompensationReceiptObservationIssueInput) {
              if (!active) throw new DaytonaSupervisorProtocolError("unavailable");
              return compensation.issue(input);
            },
          }),
          async close(): Promise<void> {
            active = false;
          },
        });
      } catch (error) {
        if (error instanceof DaytonaSupervisorProtocolError) throw error;
        throw new DaytonaSupervisorProtocolError("not-ready");
      }
    },
  });
}

interface ProvisioningRecord {
  readonly version: 1;
  readonly kind: typeof PROVISIONING_RECORD_KIND;
  readonly keyProvisioningRef: string;
  readonly binding: RuntimeBinding;
  readonly issuerKeyId: string;
  readonly publicKeySpkiPem: string;
  readonly privateKeyFile: string;
}

function snapshotProvisioningRecord(value: unknown): ProvisioningRecord {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, [
    "version",
    "kind",
    "keyProvisioningRef",
    "binding",
    "issuerKeyId",
    "publicKeySpkiPem",
    "privateKeyFile",
  ]);
  if (field(record, "version") !== 1 || field(record, "kind") !== PROVISIONING_RECORD_KIND) {
    throw new TypeError();
  }
  return Object.freeze({
    version: 1,
    kind: PROVISIONING_RECORD_KIND,
    keyProvisioningRef: safeReference(field(record, "keyProvisioningRef")),
    binding: snapshotRuntimeSupervisorPortableData(field(record, "binding")) as RuntimeBinding,
    issuerKeyId: safeReference(field(record, "issuerKeyId")),
    publicKeySpkiPem: canonicalPublicKeyPem(field(record, "publicKeySpkiPem")),
    privateKeyFile: safeReference(field(record, "privateKeyFile")),
  });
}

function snapshotRequest(
  value: DaytonaSupervisorObservationCredentialRequest
): DaytonaSupervisorObservationCredentialRequest {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, [
    "keyProvisioningRef",
    "binding",
    "issuerKeyId",
    "publicKeySpkiPem",
  ]);
  return Object.freeze({
    keyProvisioningRef: safeReference(field(record, "keyProvisioningRef")),
    binding: snapshotRuntimeSupervisorPortableData(field(record, "binding")) as RuntimeBinding,
    issuerKeyId: safeReference(field(record, "issuerKeyId")),
    publicKeySpkiPem: canonicalPublicKeyPem(field(record, "publicKeySpkiPem")),
  });
}

function assertPrivateKeyMatchesPublic(
  trustedConfigurationRoot: string,
  privateKeyFile: string,
  expectedPublicKeyPem: string
): void {
  const bytes = readTrustedConfigurationFile({
    trustedConfigurationRoot,
    filePath: privateKeyFile,
    minimumBytes: 1,
    maximumBytes: MAX_PRIVATE_KEY_BYTES,
  });
  try {
    const privateKey = createPrivateKey(bytes);
    if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
      throw new TypeError();
    }
    const actual = createPublicKey(privateKey).export({ type: "spki", format: "pem" });
    const actualBytes = Buffer.isBuffer(actual) ? actual : Buffer.from(actual, "utf8");
    const expectedBytes = Buffer.from(expectedPublicKeyPem, "utf8");
    if (
      actualBytes.byteLength !== expectedBytes.byteLength ||
      !timingSafeEqual(actualBytes, expectedBytes)
    ) {
      throw new TypeError();
    }
  } finally {
    bytes.fill(0);
  }
}

function canonicalPublicKeyPem(value: unknown): string {
  if (
    typeof value !== "string" ||
    !value.startsWith("-----BEGIN PUBLIC KEY-----\n") ||
    !value.endsWith("-----END PUBLIC KEY-----\n")
  ) {
    throw new TypeError();
  }
  const key = createPublicKey(value);
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError();
  const canonical = key.export({ type: "spki", format: "pem" });
  if (typeof canonical !== "string" || canonical !== value) throw new TypeError();
  return value;
}

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new TypeError();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of names) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) throw new TypeError();
  return value;
}

function assertNotAborted(signal: AbortSignal): void {
  try {
    AbortSignal.prototype.throwIfAborted.call(signal);
  } catch {
    throw new DaytonaSupervisorProtocolError("unavailable");
  }
}
