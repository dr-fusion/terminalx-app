import { createHash, randomBytes, timingSafeEqual, type KeyObject } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, normalize } from "node:path";
import { TextDecoder, types as nodeTypes } from "node:util";
import {
  createDaytonaAssignmentBootstrapEnvelope,
  DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_MARKER,
  digestDaytonaAssignmentBootstrapEnvelope,
  snapshotDaytonaAssignmentBootstrapInstalledDescriptor,
  type DaytonaAssignmentBootstrapInstalledDescriptor,
} from "../../../packages/daytona-supervisor/src/assignment-bootstrap";
import {
  snapshotDaytonaSupervisorBootstrapConfiguration,
  type DaytonaSupervisorBootstrapConfiguration,
} from "../../../packages/daytona-supervisor/src/daemon";
import {
  snapshotRuntimeEffectEnforcerManifest,
  type RuntimeEffectEnforcerManifest,
} from "./runtime-effect-enforcer-attestation";
import { type DaytonaAssignmentEffectManifestRecord } from "./daytona-assignment-effect-manifest";
import { snapshotHostedRuntimeActivation } from "./hosted-runtime-activation";
import { digestHostedRuntimeAssignmentPlan } from "./hosted-runtime-adapter";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import type {
  HostedRuntimeActivation,
  HostedRuntimeAssignmentPlan,
} from "./hosted-runtime-control-plane";
import { HostedControlPlaneError } from "./hosted-runtime-control-plane";
import { snapshotRuntimeSupervisorPortableData } from "./runtime-supervisor-snapshot";
import {
  DaytonaAssignmentBootstrapTransportError,
  type DaytonaAssignmentBootstrapTransport,
} from "./daytona-assignment-bootstrap-transport";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/u;
const MAX_KEY_BYTES = 64 * 1024;
const MAX_INTENT_BYTES = 256 * 1024;
const MAX_ENVELOPE_BYTES = 3 * 1024 * 1024;
const MAX_AUTHORITY_TTL_MS = 5 * 60_000;
const BINDING_DIGEST_DOMAIN = "terminalx/daytona-bootstrap-binding/v1\0";
const PROVIDER_IDENTITY_DIGEST_DOMAIN = "terminalx/daytona-provider-identity/v1\0";
const INTENT_KEY_DOMAIN = "terminalx/daytona-bootstrap-intent-key/v1\0";
const INTENT_KIND = "terminalx.daytona-assignment-bootstrap-intent" as const;
const ACTIVE_KIND = "terminalx.daytona-assignment-bootstrap-active" as const;

export interface DaytonaAssignmentBootstrapInstallRequest {
  readonly providerSandboxId: string;
  readonly plan: HostedRuntimeAssignmentPlan;
  readonly expectedRevision: number;
  readonly artifactDigest: string;
  readonly sandboxUser: "terminalx";
  readonly supervisorArtifactDigest: string;
}

export interface DaytonaAssignmentBootstrapCoordinator {
  install(
    request: DaytonaAssignmentBootstrapInstallRequest,
    signal: AbortSignal
  ): Promise<DaytonaAssignmentBootstrapInstalledDescriptor>;
  activate(
    request: DaytonaAssignmentBootstrapInstallRequest,
    installed: DaytonaAssignmentBootstrapInstalledDescriptor
  ): Promise<void>;
  retire(request: DaytonaAssignmentBootstrapInstallRequest): Promise<void>;
  /** Available only after the exact live isolation activation marker is durable. */
  resolveActivation(request: DaytonaAssignmentBootstrapInstallRequest): HostedRuntimeActivation;
  /**
   * Return the exact public manifest paired with the durable activation. This
   * is the restart-safe source for host-side receipt proof verification.
   */
  resolveEffectManifest(
    request: DaytonaAssignmentBootstrapInstallRequest
  ): DaytonaAssignmentEffectManifestRecord;
  close(): Promise<void>;
}

export interface DaytonaAssignmentBootstrapPrivateKeys {
  /** Ownership transfers to the coordinator and both buffers are always zeroed. */
  readonly observationPrivateKeyPkcs8Der: Buffer;
  readonly effectEnforcerPrivateKeyPkcs8Der: Buffer;
}

export interface CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions {
  readonly pendingRoot: string;
  readonly expectedOwnerUid: number;
  readonly authorityIssuerKeyId: string;
  readonly authoritySigningPrivateKey: KeyObject;
  readonly authorityTtlMs: number;
  /** Called only when creating a brand-new durable intent; never on replay. */
  readonly buildEffectManifest: (
    request: DaytonaAssignmentBootstrapInstallRequest
  ) => DaytonaAssignmentEffectManifestRecord;
  readonly buildBootstrapConfiguration: (
    request: DaytonaAssignmentBootstrapInstallRequest,
    effectManifest: RuntimeEffectEnforcerManifest
  ) => DaytonaSupervisorBootstrapConfiguration;
  /**
   * Resolve the already-provisioned exact assignment keys. This callback must
   * never mint replacements: a definitive expired-envelope rejection may call
   * it again to re-sign the same keys with a fresh authority window.
   */
  readonly resolvePrivateKeys: (
    request: DaytonaAssignmentBootstrapInstallRequest
  ) => DaytonaAssignmentBootstrapPrivateKeys;
  /** Release/zero the root-private resolver after all pending installs settle. */
  readonly closePrivateKeys: () => void | Promise<void>;
  readonly transport: DaytonaAssignmentBootstrapTransport;
  readonly clock: () => number;
}

export function createDurableDaytonaAssignmentBootstrapCoordinator(
  unsafeOptions: CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions
): DaytonaAssignmentBootstrapCoordinator {
  return new DurableDaytonaAssignmentBootstrapCoordinator(unsafeOptions);
}

class DurableDaytonaAssignmentBootstrapCoordinator implements DaytonaAssignmentBootstrapCoordinator {
  private readonly options: CapturedOptions;
  private readonly locks = new Map<string, Promise<unknown>>();
  private closePromise: Promise<void> | null = null;
  private closed = false;

  constructor(options: CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions) {
    this.options = captureOptions(options);
  }

  install(
    unsafeRequest: DaytonaAssignmentBootstrapInstallRequest,
    signal: AbortSignal
  ): Promise<DaytonaAssignmentBootstrapInstalledDescriptor> {
    const request = snapshotInstallRequest(unsafeRequest);
    assertSignal(signal);
    const key = intentKey(request);
    return this.exclusive(key, async () => {
      this.assertAvailable(signal);
      const intent = this.loadOrCreateIntent(key, request);
      const installedPath = join(intent.directory, "installed.json");
      if (existsSync(installedPath)) {
        const installed = validateInstalledResponse(
          readPrivateJson(installedPath, this.options.expectedOwnerUid, MAX_INTENT_BYTES),
          intent.metadata,
          request
        );
        validateActivationState(intent, installed, this.options.expectedOwnerUid);
        return installed;
      }
      if (existsSync(join(intent.directory, "active.json"))) invalidState();
      let unsafeInstalled: unknown;
      try {
        unsafeInstalled = await this.postIntent(intent, request, signal);
      } catch (error) {
        if (
          error instanceof DaytonaAssignmentBootstrapTransportError &&
          error.code === "invalid-request" &&
          sampleClock(this.options.clock) >= intent.metadata.expiresAtMs
        ) {
          // An expired exact replay has only two protocol outcomes: 200 means
          // the root committed it; 400 proves it never did. Only the latter
          // resolves the ambiguity and permits re-signing the same durable keys.
          discardDefinitivelyRejectedIntent(intent, this.options.expectedOwnerUid);
          const renewed = this.loadOrCreateIntent(key, request);
          try {
            unsafeInstalled = await this.postIntent(renewed, request, signal);
          } catch (renewalError) {
            throw mapTransportError(renewalError, signal);
          }
          return this.commitInstalledResponse(renewed, request, unsafeInstalled);
        }
        throw mapTransportError(error, signal);
      }
      return this.commitInstalledResponse(intent, request, unsafeInstalled);
    });
  }

  activate(
    unsafeRequest: DaytonaAssignmentBootstrapInstallRequest,
    unsafeInstalled: DaytonaAssignmentBootstrapInstalledDescriptor
  ): Promise<void> {
    const request = snapshotInstallRequest(unsafeRequest);
    const key = intentKey(request);
    return this.exclusive(key, async () => {
      if (this.closed) unavailable();
      const intent = this.loadIntent(key, request);
      const installed = validateInstalledResponse(unsafeInstalled, intent.metadata, request);
      const installedPath = join(intent.directory, "installed.json");
      const durableInstalled = validateInstalledResponse(
        readPrivateJson(installedPath, this.options.expectedOwnerUid, MAX_INTENT_BYTES),
        intent.metadata,
        request
      );
      if (canonicalRuntimeJson(installed) !== canonicalRuntimeJson(durableInstalled)) conflict();
      validateActivationState(intent, durableInstalled, this.options.expectedOwnerUid);
      const activePath = join(intent.directory, "active.json");
      if (existsSync(activePath)) {
        snapshotActiveMarker(
          readPrivateJson(activePath, this.options.expectedOwnerUid, MAX_INTENT_BYTES),
          installed.envelopeDigest
        );
      } else {
        writePrivateJsonExclusive(
          activePath,
          Object.freeze({
            version: 1,
            kind: ACTIVE_KIND,
            envelopeDigest: installed.envelopeDigest,
          })
        );
        fsyncDirectory(intent.directory);
      }
      const envelopePath = join(intent.directory, "envelope.bin");
      if (existsSync(envelopePath)) {
        assertPrivateFile(envelopePath, this.options.expectedOwnerUid, MAX_ENVELOPE_BYTES);
        unlinkSync(envelopePath);
        fsyncDirectory(intent.directory);
      }
    });
  }

  retire(unsafeRequest: DaytonaAssignmentBootstrapInstallRequest): Promise<void> {
    const request = snapshotInstallRequest(unsafeRequest);
    const key = intentKey(request);
    return this.exclusive(key, async () => {
      if (this.closed) unavailable();
      const directory = join(this.options.pendingRoot, key);
      const retiredDirectory = join(this.options.pendingRoot, `.retired-${key}`);
      removeRetiredIntentDirectory(
        retiredDirectory,
        this.options.expectedOwnerUid,
        this.options.pendingRoot
      );
      if (!existsSync(directory)) return;
      const intent = this.loadIntent(key, request);
      validateRetirementState(intent, request, this.options.expectedOwnerUid);
      try {
        renameSync(directory, retiredDirectory);
      } catch (error) {
        if (!existsSync(directory) && existsSync(retiredDirectory)) {
          removeRetiredIntentDirectory(
            retiredDirectory,
            this.options.expectedOwnerUid,
            this.options.pendingRoot
          );
          return;
        }
        throw error;
      }
      fsyncDirectory(this.options.pendingRoot);
      removeRetiredIntentDirectory(
        retiredDirectory,
        this.options.expectedOwnerUid,
        this.options.pendingRoot
      );
    });
  }

  resolveActivation(
    unsafeRequest: DaytonaAssignmentBootstrapInstallRequest
  ): HostedRuntimeActivation {
    const request = snapshotInstallRequest(unsafeRequest);
    if (this.closed) unavailable();
    const intent = this.loadIntent(intentKey(request), request);
    const installed = validateInstalledResponse(
      readPrivateJson(
        join(intent.directory, "installed.json"),
        this.options.expectedOwnerUid,
        MAX_INTENT_BYTES
      ),
      intent.metadata,
      request
    );
    const activePath = join(intent.directory, "active.json");
    if (!existsSync(activePath)) unavailable();
    snapshotActiveMarker(
      readPrivateJson(activePath, this.options.expectedOwnerUid, MAX_INTENT_BYTES),
      installed.envelopeDigest
    );
    return activationFromIntent(intent.metadata, request);
  }

  resolveEffectManifest(
    unsafeRequest: DaytonaAssignmentBootstrapInstallRequest
  ): DaytonaAssignmentEffectManifestRecord {
    const request = snapshotInstallRequest(unsafeRequest);
    if (this.closed) unavailable();
    const intent = this.loadIntent(intentKey(request), request);
    // Reuse the activation gate: a manifest may not become host trust merely
    // because a provisional bootstrap intent exists.
    const activation = this.resolveActivation(request);
    return captureEffectManifestRecord(
      { manifest: intent.effectRecord.manifest, activation },
      request
    );
  }

  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    this.closePromise = (async () => {
      await Promise.allSettled(this.locks.values());
      const outcomes = await Promise.allSettled([
        this.options.transport.close(),
        Promise.resolve().then(() => this.options.closePrivateKeys()),
      ]);
      if (outcomes.some((outcome) => outcome.status === "rejected")) internal();
    })();
    return this.closePromise;
  }

  private loadOrCreateIntent(
    key: string,
    request: DaytonaAssignmentBootstrapInstallRequest
  ): LoadedIntent {
    const directory = join(this.options.pendingRoot, key);
    removeRetiredIntentDirectory(
      join(this.options.pendingRoot, `.rejected-${key}`),
      this.options.expectedOwnerUid,
      this.options.pendingRoot
    );
    if (existsSync(directory)) return this.loadIntent(key, request);
    const effectRecord = captureEffectManifestRecord(
      this.options.buildEffectManifest(request),
      request
    );
    const configuration = snapshotDaytonaSupervisorBootstrapConfiguration(
      this.options.buildBootstrapConfiguration(request, effectRecord.manifest)
    );
    validateBootstrapConfiguration(configuration, request);
    if (
      canonicalRuntimeJson(configuration.effect.manifest) !==
      canonicalRuntimeJson(effectRecord.manifest)
    ) {
      conflict();
    }
    const { observationPrivateKey, effectEnforcerPrivateKey } = captureOwnedPrivateKeys(
      this.options.resolvePrivateKeys(request)
    );
    const issuedAtMs = sampleClock(this.options.clock);
    const expiresAtMs = safeAdd(issuedAtMs, this.options.authorityTtlMs);
    let envelope: Buffer;
    try {
      envelope = createDaytonaAssignmentBootstrapEnvelope({
        bootstrap: configuration,
        observationPrivateKeyPkcs8Der: observationPrivateKey,
        effectEnforcerPrivateKeyPkcs8Der: effectEnforcerPrivateKey,
        authorityIssuerKeyId: this.options.authorityIssuerKeyId,
        authoritySigningPrivateKey: this.options.authoritySigningPrivateKey,
        issuedAtMs,
        expiresAtMs,
      });
    } finally {
      observationPrivateKey.fill(0);
      effectEnforcerPrivateKey.fill(0);
    }
    try {
      const effect = effectIdentity(configuration);
      const metadata: BootstrapIntentMetadata = Object.freeze({
        version: 1,
        kind: INTENT_KIND,
        providerSandboxId: request.providerSandboxId,
        planDigest: planDigest(request.plan),
        bindingDigest: bindingDigest(request.plan.binding),
        artifactDigest: request.artifactDigest,
        supervisorArtifactDigest: request.supervisorArtifactDigest,
        assignmentPlanDigest: effectRecord.activation.assignmentPlanDigest,
        effectEnforcerPolicyDigest: effectRecord.activation.effectEnforcerPolicyDigest,
        providerIdentityCommitment: effectRecord.activation.providerIdentityCommitment,
        providerRevision: effectRecord.activation.providerRevision,
        effectManifestBindingDigest: effectRecord.activation.effectManifestBindingDigest,
        effectEnforcerSetDigest: effectRecord.activation.effectEnforcerSetDigest,
        observationIssuerKeyId: request.plan.observation.issuerKeyId,
        observationPublicKeyDigest: sha256Text(request.plan.observation.publicKeySpkiPem),
        effectEnforcerKeyId: effect.enforcerKeyId,
        effectEnforcerPublicKeyDigest: effect.publicKeySpkiDigest,
        envelopeDigest: digestDaytonaAssignmentBootstrapEnvelope(envelope),
        issuedAtMs,
        expiresAtMs,
      });
      persistNewIntent(this.options.pendingRoot, key, metadata, effectRecord.manifest, envelope);
    } finally {
      envelope.fill(0);
    }
    return this.loadIntent(key, request);
  }

  private async postIntent(
    intent: LoadedIntent,
    request: DaytonaAssignmentBootstrapInstallRequest,
    signal: AbortSignal
  ): Promise<unknown> {
    const envelope = readPrivateBytes(
      join(intent.directory, "envelope.bin"),
      this.options.expectedOwnerUid,
      MAX_ENVELOPE_BYTES
    );
    try {
      if (
        !sameDigest(
          digestDaytonaAssignmentBootstrapEnvelope(envelope),
          intent.metadata.envelopeDigest
        )
      ) {
        invalidState();
      }
      return await this.options.transport.install(request.providerSandboxId, envelope, signal);
    } finally {
      envelope.fill(0);
    }
  }

  private commitInstalledResponse(
    intent: LoadedIntent,
    request: DaytonaAssignmentBootstrapInstallRequest,
    unsafeInstalled: unknown
  ): DaytonaAssignmentBootstrapInstalledDescriptor {
    const installed = validateInstalledResponse(unsafeInstalled, intent.metadata, request);
    const installedPath = join(intent.directory, "installed.json");
    try {
      writePrivateJsonExclusive(installedPath, installed);
      fsyncDirectory(intent.directory);
      return installed;
    } catch (error) {
      // Another process can complete the same exact idempotent POST. Its
      // durable descriptor must be byte-for-byte equivalent before reuse.
      if (!existsSync(installedPath)) throw error;
      const durable = validateInstalledResponse(
        readPrivateJson(installedPath, this.options.expectedOwnerUid, MAX_INTENT_BYTES),
        intent.metadata,
        request
      );
      if (canonicalRuntimeJson(durable) !== canonicalRuntimeJson(installed)) conflict();
      return durable;
    }
  }

  private loadIntent(key: string, request: DaytonaAssignmentBootstrapInstallRequest): LoadedIntent {
    const directory = join(this.options.pendingRoot, key);
    assertPrivateDirectory(directory, this.options.expectedOwnerUid);
    const metadata = snapshotIntent(
      readPrivateJson(
        join(directory, "intent.json"),
        this.options.expectedOwnerUid,
        MAX_INTENT_BYTES
      )
    );
    validateIntent(metadata, request);
    let effectRecord: DaytonaAssignmentEffectManifestRecord;
    try {
      const manifest = snapshotRuntimeEffectEnforcerManifest(
        readPrivateJson(
          join(directory, "effect-manifest.json"),
          this.options.expectedOwnerUid,
          MAX_INTENT_BYTES
        )
      );
      effectRecord = captureEffectManifestRecord(
        { manifest, activation: activationFromIntent(metadata, request) },
        request
      );
    } catch (error) {
      if (error instanceof HostedControlPlaneError) throw error;
      invalidState();
    }
    return Object.freeze({ directory, metadata, effectRecord });
  }

  private exclusive<T>(key: string, work: () => Promise<T>): Promise<T> {
    const prior = this.locks.get(key) ?? Promise.resolve();
    const task = prior
      .catch(() => undefined)
      .then(work)
      .finally(() => {
        if (this.locks.get(key) === task) this.locks.delete(key);
      });
    this.locks.set(key, task);
    return task;
  }

  private assertAvailable(signal: AbortSignal): void {
    if (this.closed) unavailable();
    assertSignal(signal);
    if (signal.aborted) timeout();
  }
}

interface CapturedOptions extends Omit<
  CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions,
  "authorityTtlMs"
> {
  readonly authorityTtlMs: number;
}

interface BootstrapIntentMetadata {
  readonly version: 1;
  readonly kind: typeof INTENT_KIND;
  readonly providerSandboxId: string;
  readonly planDigest: string;
  readonly bindingDigest: string;
  readonly artifactDigest: string;
  readonly supervisorArtifactDigest: string;
  readonly assignmentPlanDigest: string;
  readonly effectEnforcerPolicyDigest: string;
  readonly providerIdentityCommitment: string;
  readonly providerRevision: number;
  readonly effectManifestBindingDigest: string;
  readonly effectEnforcerSetDigest: string;
  readonly observationIssuerKeyId: string;
  readonly observationPublicKeyDigest: string;
  readonly effectEnforcerKeyId: string;
  readonly effectEnforcerPublicKeyDigest: string;
  readonly envelopeDigest: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

interface LoadedIntent {
  readonly directory: string;
  readonly metadata: BootstrapIntentMetadata;
  readonly effectRecord: DaytonaAssignmentEffectManifestRecord;
}

interface BootstrapActiveMarker {
  readonly version: 1;
  readonly kind: typeof ACTIVE_KIND;
  readonly envelopeDigest: string;
}

interface CapturedPrivateKeys {
  readonly observationPrivateKey: Buffer;
  readonly effectEnforcerPrivateKey: Buffer;
}

function captureOptions(
  value: CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions
): CapturedOptions {
  const record = exactRecord(value, [
    "pendingRoot",
    "expectedOwnerUid",
    "authorityIssuerKeyId",
    "authoritySigningPrivateKey",
    "authorityTtlMs",
    "buildEffectManifest",
    "buildBootstrapConfiguration",
    "resolvePrivateKeys",
    "closePrivateKeys",
    "transport",
    "clock",
  ]);
  const pendingRoot = field(record, "pendingRoot");
  const expectedOwnerUid = field(record, "expectedOwnerUid");
  const authorityIssuerKeyId = field(record, "authorityIssuerKeyId");
  const authoritySigningPrivateKey = field(record, "authoritySigningPrivateKey");
  const authorityTtlMs = field(record, "authorityTtlMs");
  const buildEffectManifest = field(record, "buildEffectManifest");
  const buildBootstrapConfiguration = field(record, "buildBootstrapConfiguration");
  const resolvePrivateKeys = field(record, "resolvePrivateKeys");
  const closePrivateKeys = field(record, "closePrivateKeys");
  const transport = field(record, "transport");
  const clock = field(record, "clock");
  if (
    typeof pendingRoot !== "string" ||
    !isAbsolute(pendingRoot) ||
    normalize(pendingRoot) !== pendingRoot ||
    !Number.isSafeInteger(expectedOwnerUid) ||
    (expectedOwnerUid as number) < 0 ||
    typeof authorityIssuerKeyId !== "string" ||
    !SAFE_REFERENCE.test(authorityIssuerKeyId) ||
    !nodeTypes.isKeyObject(authoritySigningPrivateKey) ||
    authoritySigningPrivateKey.type !== "private" ||
    authoritySigningPrivateKey.asymmetricKeyType !== "ed25519" ||
    typeof buildEffectManifest !== "function" ||
    nodeTypes.isProxy(buildEffectManifest) ||
    typeof buildBootstrapConfiguration !== "function" ||
    nodeTypes.isProxy(buildBootstrapConfiguration) ||
    typeof resolvePrivateKeys !== "function" ||
    nodeTypes.isProxy(resolvePrivateKeys) ||
    typeof closePrivateKeys !== "function" ||
    nodeTypes.isProxy(closePrivateKeys) ||
    typeof clock !== "function" ||
    nodeTypes.isProxy(clock) ||
    !Number.isSafeInteger(authorityTtlMs) ||
    (authorityTtlMs as number) < 1 ||
    (authorityTtlMs as number) > MAX_AUTHORITY_TTL_MS
  ) {
    invalidState();
  }
  assertPrivateDirectory(pendingRoot, expectedOwnerUid as number);
  const capturedTransport = captureTransport(transport);
  return Object.freeze({
    pendingRoot,
    expectedOwnerUid: expectedOwnerUid as number,
    authorityIssuerKeyId,
    authoritySigningPrivateKey,
    authorityTtlMs: authorityTtlMs as number,
    buildEffectManifest:
      buildEffectManifest as CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions["buildEffectManifest"],
    buildBootstrapConfiguration:
      buildBootstrapConfiguration as CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions["buildBootstrapConfiguration"],
    resolvePrivateKeys:
      resolvePrivateKeys as CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions["resolvePrivateKeys"],
    closePrivateKeys:
      closePrivateKeys as CreateDurableDaytonaAssignmentBootstrapCoordinatorOptions["closePrivateKeys"],
    transport: capturedTransport,
    clock: clock as () => number,
  });
}

function captureTransport(value: unknown): DaytonaAssignmentBootstrapTransport {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value)) invalidState();
  const receiver = value as object;
  const install = captureDataMethod(receiver, "install");
  const close = captureDataMethod(receiver, "close");
  return Object.freeze({
    install: (providerSandboxId: string, envelope: Buffer, signal: AbortSignal) =>
      Reflect.apply(install, receiver, [providerSandboxId, envelope, signal]) as Promise<unknown>,
    close: () => Reflect.apply(close, receiver, []) as Promise<void>,
  });
}

function captureDataMethod(receiver: object, name: string): (...args: never[]) => unknown {
  const visited = new Set<object>();
  let current: object | null = receiver;
  for (let depth = 0; current !== null && depth < 32; depth += 1) {
    if (visited.has(current) || nodeTypes.isProxy(current)) invalidState();
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, name);
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") invalidState();
      return descriptor.value as (...args: never[]) => unknown;
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  invalidState();
}

function snapshotInstallRequest(value: unknown): DaytonaAssignmentBootstrapInstallRequest {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value)) invalidState();
  const snapshot = snapshotRuntimeSupervisorPortableData(
    value
  ) as DaytonaAssignmentBootstrapInstallRequest;
  if (
    !UUID_V4.test(snapshot.providerSandboxId) ||
    !Number.isSafeInteger(snapshot.expectedRevision) ||
    snapshot.expectedRevision < 1 ||
    snapshot.sandboxUser !== "terminalx"
  ) {
    invalidState();
  }
  digest(snapshot.artifactDigest);
  digest(snapshot.supervisorArtifactDigest);
  digest(snapshot.plan.effectEnforcerPolicyDigest);
  canonicalRuntimeJson(snapshot.plan);
  return Object.freeze(snapshot);
}

function validateBootstrapConfiguration(
  configuration: DaytonaSupervisorBootstrapConfiguration,
  request: DaytonaAssignmentBootstrapInstallRequest
): void {
  const assignment = configuration.assignment;
  if (
    canonicalRuntimeJson(assignment.plan) !== canonicalRuntimeJson(request.plan) ||
    assignment.providerSandboxId !== request.providerSandboxId ||
    assignment.expectedRevision !== request.expectedRevision ||
    assignment.sandboxUser !== request.sandboxUser ||
    !sameDigest(assignment.artifactDigest, request.artifactDigest) ||
    !sameDigest(assignment.supervisorArtifactDigest, request.supervisorArtifactDigest) ||
    !sameDigest(
      assignment.effectEnforcerSetDigest,
      snapshotRuntimeEffectEnforcerManifest(configuration.effect.manifest).authority.claimsDigest
    )
  ) {
    conflict();
  }
}

function captureOwnedPrivateKeys(value: unknown): CapturedPrivateKeys {
  let observationPrivateKey: unknown;
  let effectEnforcerPrivateKey: unknown;
  try {
    if (typeof value === "object" && value !== null && !nodeTypes.isProxy(value)) {
      const observationDescriptor = Object.getOwnPropertyDescriptor(
        value,
        "observationPrivateKeyPkcs8Der"
      );
      const effectDescriptor = Object.getOwnPropertyDescriptor(
        value,
        "effectEnforcerPrivateKeyPkcs8Der"
      );
      if (observationDescriptor && "value" in observationDescriptor) {
        observationPrivateKey = observationDescriptor.value;
      }
      if (effectDescriptor && "value" in effectDescriptor) {
        effectEnforcerPrivateKey = effectDescriptor.value;
      }
    }
    const keys = exactRecord(value, [
      "observationPrivateKeyPkcs8Der",
      "effectEnforcerPrivateKeyPkcs8Der",
    ]);
    observationPrivateKey = field(keys, "observationPrivateKeyPkcs8Der");
    effectEnforcerPrivateKey = field(keys, "effectEnforcerPrivateKeyPkcs8Der");
    if (
      !Buffer.isBuffer(observationPrivateKey) ||
      nodeTypes.isProxy(observationPrivateKey) ||
      observationPrivateKey.byteLength < 1 ||
      observationPrivateKey.byteLength > MAX_KEY_BYTES ||
      !Buffer.isBuffer(effectEnforcerPrivateKey) ||
      nodeTypes.isProxy(effectEnforcerPrivateKey) ||
      effectEnforcerPrivateKey.byteLength < 1 ||
      effectEnforcerPrivateKey.byteLength > MAX_KEY_BYTES ||
      observationPrivateKey === effectEnforcerPrivateKey
    ) {
      invalidState();
    }
    return Object.freeze({ observationPrivateKey, effectEnforcerPrivateKey });
  } catch (error) {
    if (Buffer.isBuffer(observationPrivateKey)) observationPrivateKey.fill(0);
    if (Buffer.isBuffer(effectEnforcerPrivateKey)) effectEnforcerPrivateKey.fill(0);
    if (error instanceof HostedControlPlaneError) throw error;
    invalidState();
  }
}

function effectIdentity(configuration: DaytonaSupervisorBootstrapConfiguration): {
  readonly enforcerKeyId: string;
  readonly publicKeySpkiDigest: string;
} {
  const manifest = snapshotRuntimeEffectEnforcerManifest(configuration.effect.manifest);
  const entries = manifest.enforcers.filter(
    (entry) =>
      entry.enforcerKind === "runtime" &&
      entry.allowedPurposes.includes("runtime-lifecycle") &&
      entry.allowedPurposes.includes("stale-lifecycle-effect-containment")
  );
  if (entries.length !== 1 || !entries[0]) invalidState();
  return Object.freeze({
    enforcerKeyId: entries[0].enforcerKeyId,
    publicKeySpkiDigest: entries[0].publicKeySpkiDigest,
  });
}

function captureEffectManifestRecord(
  value: unknown,
  request: DaytonaAssignmentBootstrapInstallRequest
): DaytonaAssignmentEffectManifestRecord {
  const record = exactRecord(value, ["manifest", "activation"]);
  const manifest = snapshotRuntimeEffectEnforcerManifest(field(record, "manifest"));
  const activation = snapshotHostedRuntimeActivation(field(record, "activation"));
  if (
    canonicalRuntimeJson(activation.binding) !== canonicalRuntimeJson(request.plan.binding) ||
    activation.runtimeAuthorizationGeneration !== request.plan.runtimeAuthorizationGeneration ||
    !sameDigest(activation.assignmentPlanDigest, planDigest(request.plan)) ||
    !sameDigest(activation.effectEnforcerPolicyDigest, request.plan.effectEnforcerPolicyDigest) ||
    !sameDigest(
      activation.providerIdentityCommitment,
      providerIdentity(request.providerSandboxId)
    ) ||
    activation.providerRevision !== request.expectedRevision ||
    !sameDigest(activation.effectManifestBindingDigest, manifest.effectManifestBindingDigest) ||
    !sameDigest(activation.effectEnforcerSetDigest, manifest.authority.claimsDigest)
  ) {
    conflict();
  }
  return Object.freeze({ manifest, activation });
}

function activationFromIntent(
  intent: BootstrapIntentMetadata,
  request: DaytonaAssignmentBootstrapInstallRequest
): HostedRuntimeActivation {
  return snapshotHostedRuntimeActivation({
    version: 1,
    kind: "hosted-runtime.activation",
    binding: request.plan.binding,
    runtimeAuthorizationGeneration: request.plan.runtimeAuthorizationGeneration,
    assignmentPlanDigest: intent.assignmentPlanDigest,
    effectEnforcerPolicyDigest: intent.effectEnforcerPolicyDigest,
    providerIdentityCommitment: intent.providerIdentityCommitment,
    providerRevision: intent.providerRevision,
    effectManifestBindingDigest: intent.effectManifestBindingDigest,
    effectEnforcerSetDigest: intent.effectEnforcerSetDigest,
  });
}

function validateInstalledResponse(
  value: unknown,
  intent: BootstrapIntentMetadata,
  request: DaytonaAssignmentBootstrapInstallRequest
): DaytonaAssignmentBootstrapInstalledDescriptor {
  let installed: DaytonaAssignmentBootstrapInstalledDescriptor;
  try {
    installed = snapshotDaytonaAssignmentBootstrapInstalledDescriptor(value);
  } catch {
    invalidState();
  }
  if (
    installed.installedMarker !== DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_MARKER ||
    installed.supervisorReady !== false ||
    !sameDigest(installed.envelopeDigest, intent.envelopeDigest) ||
    !sameDigest(
      installed.providerIdentityCommitment,
      providerIdentity(request.providerSandboxId)
    ) ||
    installed.providerRevision !== request.expectedRevision ||
    !sameDigest(installed.planDigest, intent.planDigest) ||
    !sameDigest(installed.assignmentPlanDigest, intent.assignmentPlanDigest) ||
    !sameDigest(installed.effectEnforcerPolicyDigest, intent.effectEnforcerPolicyDigest) ||
    !sameDigest(installed.effectManifestBindingDigest, intent.effectManifestBindingDigest) ||
    !sameDigest(installed.effectEnforcerSetDigest, intent.effectEnforcerSetDigest) ||
    !sameDigest(installed.bindingDigest, intent.bindingDigest) ||
    installed.observationIssuerKeyId !== intent.observationIssuerKeyId ||
    !sameDigest(installed.observationPublicKeyDigest, intent.observationPublicKeyDigest) ||
    installed.effectEnforcerKeyId !== intent.effectEnforcerKeyId ||
    !sameDigest(installed.effectEnforcerPublicKeyDigest, intent.effectEnforcerPublicKeyDigest) ||
    !sameDigest(installed.supervisorArtifactDigest, intent.supervisorArtifactDigest)
  ) {
    conflict();
  }
  return installed;
}

function snapshotActiveMarker(
  value: unknown,
  expectedEnvelopeDigest: string
): BootstrapActiveMarker {
  const record = exactRecord(value, ["version", "kind", "envelopeDigest"]);
  const envelopeDigest = digest(field(record, "envelopeDigest"));
  if (
    field(record, "version") !== 1 ||
    field(record, "kind") !== ACTIVE_KIND ||
    !sameDigest(envelopeDigest, expectedEnvelopeDigest)
  ) {
    invalidState();
  }
  return Object.freeze({ version: 1, kind: ACTIVE_KIND, envelopeDigest });
}

function validateActivationState(
  intent: LoadedIntent,
  installed: DaytonaAssignmentBootstrapInstalledDescriptor,
  expectedOwnerUid: number
): void {
  const activePath = join(intent.directory, "active.json");
  const envelopePath = join(intent.directory, "envelope.bin");
  if (existsSync(activePath)) {
    snapshotActiveMarker(
      readPrivateJson(activePath, expectedOwnerUid, MAX_INTENT_BYTES),
      installed.envelopeDigest
    );
    if (existsSync(envelopePath)) {
      const envelope = readPrivateBytes(envelopePath, expectedOwnerUid, MAX_ENVELOPE_BYTES);
      try {
        if (
          !sameDigest(digestDaytonaAssignmentBootstrapEnvelope(envelope), installed.envelopeDigest)
        ) {
          invalidState();
        }
      } finally {
        envelope.fill(0);
      }
    }
    return;
  }
  // The envelope is retained until the live isolation handshake is durably
  // recorded. Missing both files would otherwise turn a partial activation
  // into an unrecoverable false success.
  if (!existsSync(envelopePath)) invalidState();
  const envelope = readPrivateBytes(envelopePath, expectedOwnerUid, MAX_ENVELOPE_BYTES);
  try {
    if (!sameDigest(digestDaytonaAssignmentBootstrapEnvelope(envelope), installed.envelopeDigest)) {
      invalidState();
    }
  } finally {
    envelope.fill(0);
  }
}

function validateRetirementState(
  intent: LoadedIntent,
  request: DaytonaAssignmentBootstrapInstallRequest,
  expectedOwnerUid: number
): void {
  const installedPath = join(intent.directory, "installed.json");
  let installed: DaytonaAssignmentBootstrapInstalledDescriptor | undefined;
  if (existsSync(installedPath)) {
    installed = validateInstalledResponse(
      readPrivateJson(installedPath, expectedOwnerUid, MAX_INTENT_BYTES),
      intent.metadata,
      request
    );
  }
  const activePath = join(intent.directory, "active.json");
  if (existsSync(activePath)) {
    if (!installed) invalidState();
    snapshotActiveMarker(
      readPrivateJson(activePath, expectedOwnerUid, MAX_INTENT_BYTES),
      installed.envelopeDigest
    );
  }
  const envelopePath = join(intent.directory, "envelope.bin");
  if (existsSync(envelopePath)) {
    const envelope = readPrivateBytes(envelopePath, expectedOwnerUid, MAX_ENVELOPE_BYTES);
    try {
      if (
        !sameDigest(
          digestDaytonaAssignmentBootstrapEnvelope(envelope),
          intent.metadata.envelopeDigest
        )
      ) {
        invalidState();
      }
    } finally {
      envelope.fill(0);
    }
  }
}

function discardDefinitivelyRejectedIntent(intent: LoadedIntent, expectedOwnerUid: number): void {
  const installedPath = join(intent.directory, "installed.json");
  const activePath = join(intent.directory, "active.json");
  if (existsSync(installedPath) || existsSync(activePath)) invalidState();
  const envelopePath = join(intent.directory, "envelope.bin");
  const envelope = readPrivateBytes(envelopePath, expectedOwnerUid, MAX_ENVELOPE_BYTES);
  try {
    if (
      !sameDigest(
        digestDaytonaAssignmentBootstrapEnvelope(envelope),
        intent.metadata.envelopeDigest
      )
    ) {
      invalidState();
    }
  } finally {
    envelope.fill(0);
  }
  const pendingRoot = dirname(intent.directory);
  const rejectedDirectory = join(pendingRoot, `.rejected-${basename(intent.directory)}`);
  if (existsSync(rejectedDirectory)) invalidState();
  renameSync(intent.directory, rejectedDirectory);
  fsyncDirectory(pendingRoot);
  removeRetiredIntentDirectory(rejectedDirectory, expectedOwnerUid, pendingRoot);
}

function persistNewIntent(
  root: string,
  key: string,
  metadata: BootstrapIntentMetadata,
  effectManifest: RuntimeEffectEnforcerManifest,
  envelope: Buffer
): void {
  const temporary = join(root, `.intent-${key}-${process.pid}-${randomBytes(12).toString("hex")}`);
  const final = join(root, key);
  mkdirSync(temporary, { mode: 0o700 });
  chmodSync(temporary, 0o700);
  try {
    writePrivateJsonExclusive(join(temporary, "intent.json"), metadata);
    writePrivateJsonExclusive(join(temporary, "effect-manifest.json"), effectManifest);
    writePrivateBytesExclusive(join(temporary, "envelope.bin"), envelope);
    fsyncDirectory(temporary);
    renameSync(temporary, final);
    fsyncDirectory(root);
  } catch (error) {
    removeKnownIntentDirectory(temporary);
    // A concurrent process may have won the one-way rename. Its exact durable
    // intent is validated by the caller before any network request is sent.
    if (existsSync(final)) return;
    throw error;
  }
}

function snapshotIntent(value: unknown): BootstrapIntentMetadata {
  const record = exactRecord(value, [
    "version",
    "kind",
    "providerSandboxId",
    "planDigest",
    "bindingDigest",
    "artifactDigest",
    "supervisorArtifactDigest",
    "assignmentPlanDigest",
    "effectEnforcerPolicyDigest",
    "providerIdentityCommitment",
    "providerRevision",
    "effectManifestBindingDigest",
    "effectEnforcerSetDigest",
    "observationIssuerKeyId",
    "observationPublicKeyDigest",
    "effectEnforcerKeyId",
    "effectEnforcerPublicKeyDigest",
    "envelopeDigest",
    "issuedAtMs",
    "expiresAtMs",
  ]);
  if (field(record, "version") !== 1 || field(record, "kind") !== INTENT_KIND) invalidState();
  const issuedAtMs = nonNegativeInteger(field(record, "issuedAtMs"));
  const expiresAtMs = positiveInteger(field(record, "expiresAtMs"));
  if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > MAX_AUTHORITY_TTL_MS) {
    invalidState();
  }
  return Object.freeze({
    version: 1,
    kind: INTENT_KIND,
    providerSandboxId: sandboxId(field(record, "providerSandboxId")),
    planDigest: digest(field(record, "planDigest")),
    bindingDigest: digest(field(record, "bindingDigest")),
    artifactDigest: digest(field(record, "artifactDigest")),
    supervisorArtifactDigest: digest(field(record, "supervisorArtifactDigest")),
    assignmentPlanDigest: digest(field(record, "assignmentPlanDigest")),
    effectEnforcerPolicyDigest: digest(field(record, "effectEnforcerPolicyDigest")),
    providerIdentityCommitment: digest(field(record, "providerIdentityCommitment")),
    providerRevision: positiveInteger(field(record, "providerRevision")),
    effectManifestBindingDigest: digest(field(record, "effectManifestBindingDigest")),
    effectEnforcerSetDigest: digest(field(record, "effectEnforcerSetDigest")),
    observationIssuerKeyId: safeReference(field(record, "observationIssuerKeyId")),
    observationPublicKeyDigest: digest(field(record, "observationPublicKeyDigest")),
    effectEnforcerKeyId: safeReference(field(record, "effectEnforcerKeyId")),
    effectEnforcerPublicKeyDigest: digest(field(record, "effectEnforcerPublicKeyDigest")),
    envelopeDigest: digest(field(record, "envelopeDigest")),
    issuedAtMs,
    expiresAtMs,
  });
}

function validateIntent(
  intent: BootstrapIntentMetadata,
  request: DaytonaAssignmentBootstrapInstallRequest
): void {
  if (
    intent.providerSandboxId !== request.providerSandboxId ||
    !sameDigest(intent.planDigest, planDigest(request.plan)) ||
    !sameDigest(intent.bindingDigest, bindingDigest(request.plan.binding)) ||
    !sameDigest(intent.artifactDigest, request.artifactDigest) ||
    !sameDigest(intent.supervisorArtifactDigest, request.supervisorArtifactDigest) ||
    !sameDigest(intent.effectEnforcerPolicyDigest, request.plan.effectEnforcerPolicyDigest) ||
    intent.providerRevision !== request.expectedRevision ||
    !sameDigest(intent.providerIdentityCommitment, providerIdentity(request.providerSandboxId)) ||
    intent.observationIssuerKeyId !== request.plan.observation.issuerKeyId ||
    !sameDigest(
      intent.observationPublicKeyDigest,
      sha256Text(request.plan.observation.publicKeySpkiPem)
    )
  ) {
    conflict();
  }
}

function intentKey(request: DaytonaAssignmentBootstrapInstallRequest): string {
  return sha256Text(
    `${INTENT_KEY_DOMAIN}${canonicalRuntimeJson({
      providerSandboxId: request.providerSandboxId,
      binding: request.plan.binding,
      keyProvisioningRef: request.plan.observation.keyProvisioningRef,
    })}`
  );
}

function planDigest(plan: HostedRuntimeAssignmentPlan): string {
  return digestHostedRuntimeAssignmentPlan(plan);
}

function bindingDigest(binding: unknown): string {
  return sha256Text(`${BINDING_DIGEST_DOMAIN}${canonicalRuntimeJson(binding)}`);
}

function providerIdentity(providerSandboxId: string): string {
  return sha256Text(`${PROVIDER_IDENTITY_DIGEST_DOMAIN}${providerSandboxId}`);
}

function readPrivateJson(path: string, uid: number, maximumBytes: number): unknown {
  const bytes = readPrivateBytes(path, uid, maximumBytes);
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = snapshotRuntimeSupervisorPortableData(JSON.parse(text));
    if (canonicalRuntimeJson(value) !== text) invalidState();
    return value;
  } catch (error) {
    if (error instanceof HostedControlPlaneError) throw error;
    invalidState();
  } finally {
    bytes.fill(0);
  }
}

function readPrivateBytes(path: string, uid: number, maximumBytes: number): Buffer {
  const descriptor = openSync(path, fsConstants.O_RDONLY | noFollowFlag());
  try {
    assertPrivateFileDescriptor(path, descriptor, uid, maximumBytes);
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function assertPrivateFile(path: string, uid: number, maximumBytes: number): void {
  const descriptor = openSync(path, fsConstants.O_RDONLY | noFollowFlag());
  try {
    assertPrivateFileDescriptor(path, descriptor, uid, maximumBytes);
  } finally {
    closeSync(descriptor);
  }
}

function assertPrivateFileDescriptor(
  path: string,
  descriptor: number,
  uid: number,
  maximumBytes: number
): void {
  const stat = fstatSync(descriptor);
  if (
    realpathSync.native(path) !== path ||
    !stat.isFile() ||
    stat.nlink !== 1 ||
    stat.uid !== uid ||
    (stat.mode & 0o777) !== 0o600 ||
    stat.size < 1 ||
    stat.size > maximumBytes
  ) {
    invalidState();
  }
}

function assertPrivateDirectory(path: string, uid: number): void {
  const stat = lstatSync(path);
  if (
    realpathSync.native(path) !== path ||
    stat.isSymbolicLink() ||
    !stat.isDirectory() ||
    stat.uid !== uid ||
    (stat.mode & 0o777) !== 0o700
  ) {
    invalidState();
  }
}

function writePrivateJsonExclusive(path: string, value: unknown): void {
  const bytes = Buffer.from(canonicalRuntimeJson(value), "utf8");
  try {
    writePrivateBytesExclusive(path, bytes);
  } finally {
    bytes.fill(0);
  }
}

function writePrivateBytesExclusive(path: string, bytes: Buffer): void {
  let descriptor = -1;
  try {
    descriptor = openSync(
      path,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | noFollowFlag(),
      0o600
    );
    writeFileSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
  chmodSync(path, 0o600);
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, fsConstants.O_RDONLY | noFollowFlag());
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function removeKnownIntentDirectory(directory: string): void {
  if (!existsSync(directory)) return;
  for (const name of ["envelope.bin", "effect-manifest.json", "intent.json"] as const) {
    const path = join(directory, name);
    if (existsSync(path)) unlinkSync(path);
  }
  rmdirSync(directory);
}

function removeRetiredIntentDirectory(
  directory: string,
  expectedOwnerUid: number,
  pendingRoot: string
): void {
  if (!existsSync(directory)) return;
  assertPrivateDirectory(directory, expectedOwnerUid);
  for (const name of [
    "active.json",
    "installed.json",
    "envelope.bin",
    "effect-manifest.json",
    "intent.json",
  ] as const) {
    const path = join(directory, name);
    if (!existsSync(path)) continue;
    assertPrivateFile(path, expectedOwnerUid, MAX_ENVELOPE_BYTES);
    unlinkSync(path);
  }
  rmdirSync(directory);
  fsyncDirectory(pendingRoot);
}

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
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
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    invalidState();
  }
  for (const name of names) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalidState();
  return descriptor.value;
}

function mapTransportError(error: unknown, signal: AbortSignal): HostedControlPlaneError {
  if (signal.aborted) return new HostedControlPlaneError("timeout");
  if (error instanceof DaytonaAssignmentBootstrapTransportError) {
    if (error.code === "invalid-request") return new HostedControlPlaneError("invalid-state");
    if (error.code === "conflict") return new HostedControlPlaneError("conflict");
    if (error.code === "permission-denied") return new HostedControlPlaneError("permission-denied");
  }
  return new HostedControlPlaneError("unavailable");
}

function sandboxId(value: unknown): string {
  if (typeof value !== "string" || !UUID_V4.test(value)) invalidState();
  return value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) invalidState();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) invalidState();
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) invalidState();
  return value as number;
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) invalidState();
  return value as number;
}

function sampleClock(clock: () => number): number {
  return nonNegativeInteger(clock());
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) invalidState();
  return result;
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sameDigest(left: string, right: string): boolean {
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function assertSignal(signal: AbortSignal): void {
  if (!(signal instanceof AbortSignal) || nodeTypes.isProxy(signal)) invalidState();
}

function noFollowFlag(): number {
  return fsConstants.O_NOFOLLOW ?? 0;
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

function timeout(): never {
  throw new HostedControlPlaneError("timeout");
}

function internal(): never {
  throw new HostedControlPlaneError("internal");
}
