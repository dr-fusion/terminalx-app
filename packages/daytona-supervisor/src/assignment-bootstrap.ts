import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as signEd25519,
  timingSafeEqual,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, normalize } from "node:path";
import { TextDecoder, types as nodeTypes } from "node:util";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import {
  createRuntimeEffectEnforcerTrustRegistry,
  snapshotRuntimeEffectEnforcerManifest,
} from "../../../src/lib/runtime/runtime-effect-enforcer-attestation";
import { verifyDaytonaAssignmentEffectManifestBinding } from "../../../src/lib/runtime/daytona-assignment-effect-manifest";
import { HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN } from "../../../src/lib/runtime/hosted-runtime-control-plane";
import {
  snapshotDaytonaSupervisorBootstrapConfiguration,
  type DaytonaSupervisorBootstrapConfiguration,
} from "./daemon";
import { assertPinnedRootExecutable } from "./pinned-root-executable";

export const DAYTONA_ASSIGNMENT_BOOTSTRAP_REQUEST_MEDIA_TYPE =
  "application/vnd.terminalx.assignment-bootstrap.v1" as const;
export const DAYTONA_ASSIGNMENT_BOOTSTRAP_RESPONSE_MEDIA_TYPE =
  "application/vnd.terminalx.assignment-bootstrap-installed.v1+json" as const;
export const DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_REQUEST_BYTES = 3 * 1024 * 1024;
export const DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_RESPONSE_BYTES = 64 * 1024;
export const DAYTONA_ASSIGNMENT_BOOTSTRAP_EXECUTABLE =
  "/usr/local/libexec/terminalx/terminalx-assignment-bootstrap" as const;
export const DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_MARKER =
  "/run/terminalx-root/assignment.installed.json" as const;
export const DAYTONA_ASSIGNMENT_BOOTSTRAP_KIND = "terminalx.daytona-assignment-bootstrap" as const;
export const DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_KIND =
  "terminalx.daytona-assignment-bootstrap-installed" as const;
export const DAYTONA_ASSIGNMENT_BOOTSTRAP_CLAIMS_DIGEST_DOMAIN =
  "terminalx/daytona-assignment-bootstrap-claims/v1\0" as const;
export const DAYTONA_ASSIGNMENT_BOOTSTRAP_AUTHORITY_SIGNATURE_DOMAIN =
  "terminalx/daytona-assignment-bootstrap-authority/v1\0" as const;
export const DAYTONA_SANDBOX_DEPLOYMENT_BINDING_KIND =
  "terminalx.daytona-sandbox-deployment-binding" as const;
export const DAYTONA_SANDBOX_DEPLOYMENT_BINDING_CLAIMS_DIGEST_DOMAIN =
  "terminalx/daytona-sandbox-deployment-binding-claims/v1\0" as const;
export const DAYTONA_SANDBOX_DEPLOYMENT_BINDING_SIGNATURE_DOMAIN =
  "terminalx/daytona-sandbox-deployment-binding-authority/v1\0" as const;

const HEADER_MAX_BYTES = 2 * 1024 * 1024;
const PRIVATE_KEY_MAX_BYTES = 64 * 1024;
const MAX_AUTHORITY_TTL_MS = 5 * 60_000;
const MAX_DEPLOYMENT_BINDING_TTL_MS = 5 * 60_000;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/u;
const OBSERVATION_ISSUER_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TERMINALX_SANDBOX_HOSTNAME = "terminalx-sandbox" as const;
const PROVIDER_IDENTITY_DIGEST_DOMAIN = "terminalx/daytona-provider-identity/v1\0";
const BINDING_DIGEST_DOMAIN = "terminalx/daytona-bootstrap-binding/v1\0";
const ENVELOPE_DIGEST_DOMAIN = "terminalx/daytona-assignment-bootstrap-envelope/v1\0";
const AUTHORITY_ISSUER = "platform-security" as const;
const AUTHORITY_AUDIENCE = "terminalx-sandbox-init" as const;
const AUTHORITY_CAPABILITY = "runtime.assignment.bootstrap" as const;
const DEPLOYMENT_BINDING_ISSUER = "daytona-runner" as const;
const DEPLOYMENT_BINDING_AUDIENCE = "terminalx-assignment-bootstrap" as const;
const DEPLOYMENT_BINDING_CAPABILITY = "sandbox.deployment.bind" as const;
const OBSERVATION_SECTION = "observation-ed25519-pkcs8" as const;
const EFFECT_ENFORCER_SECTION = "effect-enforcer-ed25519-pkcs8" as const;

export type DaytonaAssignmentBootstrapExitCode = 64 | 73 | 74;

export class DaytonaAssignmentBootstrapError extends Error {
  constructor(readonly exitCode: DaytonaAssignmentBootstrapExitCode) {
    super("TerminalX assignment bootstrap failed closed");
    this.name = "DaytonaAssignmentBootstrapError";
  }
}

export interface DaytonaAssignmentBootstrapHeader {
  readonly version: 1;
  readonly kind: typeof DAYTONA_ASSIGNMENT_BOOTSTRAP_KIND;
  readonly bootstrap: DaytonaSupervisorBootstrapConfiguration;
  readonly sections: readonly [
    Readonly<{
      kind: typeof OBSERVATION_SECTION;
      bytes: number;
      sha256: string;
    }>,
    Readonly<{
      kind: typeof EFFECT_ENFORCER_SECTION;
      bytes: number;
      sha256: string;
    }>,
  ];
  readonly authority: Readonly<{
    issuer: typeof AUTHORITY_ISSUER;
    issuerKeyId: string;
    audience: typeof AUTHORITY_AUDIENCE;
    capability: typeof AUTHORITY_CAPABILITY;
    claimsDigest: string;
    issuedAtMs: number;
    expiresAtMs: number;
    signature: string;
  }>;
}

export interface DaytonaAssignmentBootstrapInstalledDescriptor {
  readonly version: 1;
  readonly kind: typeof DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_KIND;
  readonly envelopeDigest: string;
  readonly providerIdentityCommitment: string;
  readonly providerRevision: number;
  readonly planDigest: string;
  readonly assignmentPlanDigest: string;
  readonly effectEnforcerPolicyDigest: string;
  readonly effectManifestBindingDigest: string;
  readonly effectEnforcerSetDigest: string;
  readonly bindingDigest: string;
  readonly observationIssuerKeyId: string;
  readonly observationPublicKeyDigest: string;
  readonly effectEnforcerKeyId: string;
  readonly effectEnforcerPublicKeyDigest: string;
  readonly stateVerificationPublicKeySpkiPem: string;
  readonly stateVerificationPublicKeyDigest: string;
  readonly supervisorArtifactDigest: string;
  readonly installedMarker: string;
  /** Activation is a separate live relay isolation.attest handshake. */
  readonly supervisorReady: false;
}

export interface CreateDaytonaAssignmentBootstrapEnvelopeOptions {
  readonly bootstrap: DaytonaSupervisorBootstrapConfiguration;
  readonly observationPrivateKeyPkcs8Der: Buffer;
  readonly effectEnforcerPrivateKeyPkcs8Der: Buffer;
  readonly authorityIssuerKeyId: string;
  readonly authoritySigningPrivateKey: KeyObject;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

export interface ProvisionDaytonaAssignmentBootstrapOptions {
  readonly runtimeRoot: string;
  readonly stateRoot: string;
  readonly authorityPinFile: string;
  readonly imageTrustPinFile: string;
  readonly deploymentBindingFile: string;
  readonly hostnameFile: string;
  readonly expectedOwnerUid: number;
  readonly expectedPeerCredentialExecutable: string;
  readonly expectedEffectExecutable: string;
  readonly expectedNodeExecutable: string;
  readonly expectedSupervisorSocket: string;
  readonly clock?: () => number;
}

/** Build and sign a binary envelope without stringifying either private key. */
export function createDaytonaAssignmentBootstrapEnvelope(
  unsafeOptions: CreateDaytonaAssignmentBootstrapEnvelopeOptions
): Buffer {
  const options = captureCreateOptions(unsafeOptions);
  const observation = Buffer.from(options.observationPrivateKeyPkcs8Der);
  const effectEnforcer = Buffer.from(options.effectEnforcerPrivateKeyPkcs8Der);
  try {
    assertObservationPrivateKeyMatchesBootstrap(options.bootstrap, observation);
    effectEnforcerIdentity(options.bootstrap, effectEnforcer);
    const claims = Object.freeze({
      version: 1 as const,
      kind: DAYTONA_ASSIGNMENT_BOOTSTRAP_KIND,
      bootstrap: options.bootstrap,
      sections: Object.freeze([
        Object.freeze({
          kind: OBSERVATION_SECTION,
          bytes: observation.byteLength,
          sha256: rawSha256(observation),
        }),
        Object.freeze({
          kind: EFFECT_ENFORCER_SECTION,
          bytes: effectEnforcer.byteLength,
          sha256: rawSha256(effectEnforcer),
        }),
      ] as const),
    });
    const claimsDigest = digestCanonical(DAYTONA_ASSIGNMENT_BOOTSTRAP_CLAIMS_DIGEST_DOMAIN, claims);
    const statement = Object.freeze({
      version: 1,
      issuer: AUTHORITY_ISSUER,
      issuerKeyId: options.authorityIssuerKeyId,
      audience: AUTHORITY_AUDIENCE,
      capability: AUTHORITY_CAPABILITY,
      claimsDigest,
      issuedAtMs: options.issuedAtMs,
      expiresAtMs: options.expiresAtMs,
    });
    const signature = signEd25519(
      null,
      Buffer.from(
        `${DAYTONA_ASSIGNMENT_BOOTSTRAP_AUTHORITY_SIGNATURE_DOMAIN}${canonicalRuntimeJson(statement)}`,
        "utf8"
      ),
      options.authoritySigningPrivateKey
    ).toString("base64url");
    if (!SIGNATURE.test(signature)) malformed();
    const header: DaytonaAssignmentBootstrapHeader = Object.freeze({
      ...claims,
      authority: Object.freeze({
        issuer: AUTHORITY_ISSUER,
        issuerKeyId: options.authorityIssuerKeyId,
        audience: AUTHORITY_AUDIENCE,
        capability: AUTHORITY_CAPABILITY,
        claimsDigest,
        issuedAtMs: options.issuedAtMs,
        expiresAtMs: options.expiresAtMs,
        signature,
      }),
    });
    const headerBytes = Buffer.from(canonicalRuntimeJson(header), "utf8");
    if (headerBytes.byteLength < 2 || headerBytes.byteLength > HEADER_MAX_BYTES) {
      headerBytes.fill(0);
      malformed();
    }
    const total = 4 + headerBytes.byteLength + observation.byteLength + effectEnforcer.byteLength;
    if (total > DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_REQUEST_BYTES) {
      headerBytes.fill(0);
      malformed();
    }
    const result = Buffer.allocUnsafe(total);
    result.writeUInt32BE(headerBytes.byteLength, 0);
    headerBytes.copy(result, 4);
    observation.copy(result, 4 + headerBytes.byteLength);
    effectEnforcer.copy(result, 4 + headerBytes.byteLength + observation.byteLength);
    headerBytes.fill(0);
    return result;
  } finally {
    observation.fill(0);
    effectEnforcer.fill(0);
  }
}

export function digestDaytonaAssignmentBootstrapEnvelope(envelope: Uint8Array): string {
  if (!(envelope instanceof Uint8Array) || envelope.byteLength < 1) malformed();
  return digestBytes(ENVELOPE_DIGEST_DOMAIN, envelope);
}

/** Takes ownership of and always zeroes the complete envelope. */
export function provisionDaytonaAssignmentBootstrap(
  envelope: Buffer,
  unsafeOptions: ProvisionDaytonaAssignmentBootstrapOptions
): DaytonaAssignmentBootstrapInstalledDescriptor {
  if (!Buffer.isBuffer(envelope)) malformed();
  const options = captureProvisionOptions(unsafeOptions);
  try {
    assertEffectiveUid(options.expectedOwnerUid);
    assertPrivateDirectory(options.runtimeRoot, options.expectedOwnerUid);
    assertPrivateDirectory(options.stateRoot, options.expectedOwnerUid);
    const envelopeDigest = digestBytes(ENVELOPE_DIGEST_DOMAIN, envelope);
    const installedMarker = join(options.runtimeRoot, "assignment.installed.json");
    const assignmentDirectory = join(options.runtimeRoot, "assignment");
    let existing: DaytonaAssignmentBootstrapInstalledDescriptor | undefined;
    let committedReplay = false;
    if (existsSync(installedMarker)) {
      existing = readInstalledDescriptor(installedMarker, options.expectedOwnerUid);
      if (!sameDigest(existing.envelopeDigest, envelopeDigest)) conflict();
      committedReplay = true;
    } else if (existsSync(assignmentDirectory)) {
      const metadata = readProvisioningMetadata(
        join(assignmentDirectory, "provisioning-metadata.json"),
        options.expectedOwnerUid
      );
      if (!sameDigest(metadata.envelopeDigest, envelopeDigest)) conflict();
      committedReplay = true;
    }
    const decoded = decodeAndVerifyEnvelope(envelope, options, !committedReplay);
    try {
      validateProductionBootstrap(decoded.header.bootstrap, options);
      validateImageOwnedPins(decoded.header.bootstrap, options);
      if (!committedReplay) {
        installAssignment(decoded, envelopeDigest, options);
      }
      const descriptor = validateInstalledAssignment(decoded, envelopeDigest, options);
      if (existing && canonicalRuntimeJson(existing) !== canonicalRuntimeJson(descriptor)) {
        conflict();
      }
      if (!existsSync(installedMarker)) {
        writeInstalledMarker(installedMarker, descriptor, options.runtimeRoot);
      }
      return descriptor;
    } finally {
      decoded.observationPrivateKey.fill(0);
      decoded.effectEnforcerPrivateKey.fill(0);
    }
  } catch (error) {
    if (error instanceof DaytonaAssignmentBootstrapError) throw error;
    unavailable();
  } finally {
    envelope.fill(0);
  }
}

interface CapturedCreateOptions {
  readonly bootstrap: DaytonaSupervisorBootstrapConfiguration;
  readonly observationPrivateKeyPkcs8Der: Buffer;
  readonly effectEnforcerPrivateKeyPkcs8Der: Buffer;
  readonly authorityIssuerKeyId: string;
  readonly authoritySigningPrivateKey: KeyObject;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

interface CapturedProvisionOptions extends ProvisionDaytonaAssignmentBootstrapOptions {
  readonly clock: () => number;
}

interface DecodedEnvelope {
  readonly header: DaytonaAssignmentBootstrapHeader;
  readonly observationPrivateKey: Buffer;
  readonly effectEnforcerPrivateKey: Buffer;
}

function captureCreateOptions(
  value: CreateDaytonaAssignmentBootstrapEnvelopeOptions
): CapturedCreateOptions {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value)) malformed();
  const bootstrap = snapshotDaytonaSupervisorBootstrapConfiguration(value.bootstrap);
  observationIssuerKeyId(bootstrap.assignment.plan.observation.issuerKeyId);
  if (
    !Buffer.isBuffer(value.observationPrivateKeyPkcs8Der) ||
    value.observationPrivateKeyPkcs8Der.byteLength < 1 ||
    value.observationPrivateKeyPkcs8Der.byteLength > PRIVATE_KEY_MAX_BYTES ||
    !Buffer.isBuffer(value.effectEnforcerPrivateKeyPkcs8Der) ||
    value.effectEnforcerPrivateKeyPkcs8Der.byteLength < 1 ||
    value.effectEnforcerPrivateKeyPkcs8Der.byteLength > PRIVATE_KEY_MAX_BYTES ||
    !(value.authoritySigningPrivateKey instanceof Object) ||
    value.authoritySigningPrivateKey.type !== "private" ||
    value.authoritySigningPrivateKey.asymmetricKeyType !== "ed25519"
  ) {
    malformed();
  }
  const issuedAtMs = nonNegativeInteger(value.issuedAtMs);
  const expiresAtMs = positiveInteger(value.expiresAtMs);
  if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > MAX_AUTHORITY_TTL_MS) malformed();
  return Object.freeze({
    bootstrap,
    observationPrivateKeyPkcs8Der: value.observationPrivateKeyPkcs8Der,
    effectEnforcerPrivateKeyPkcs8Der: value.effectEnforcerPrivateKeyPkcs8Der,
    authorityIssuerKeyId: safeReference(value.authorityIssuerKeyId),
    authoritySigningPrivateKey: value.authoritySigningPrivateKey,
    issuedAtMs,
    expiresAtMs,
  });
}

function captureProvisionOptions(
  value: ProvisionDaytonaAssignmentBootstrapOptions
): CapturedProvisionOptions {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value)) malformed();
  const paths = [
    value.runtimeRoot,
    value.stateRoot,
    value.authorityPinFile,
    value.imageTrustPinFile,
    value.deploymentBindingFile,
    value.hostnameFile,
    value.expectedPeerCredentialExecutable,
    value.expectedEffectExecutable,
    value.expectedNodeExecutable,
    value.expectedSupervisorSocket,
  ];
  if (
    paths.some(
      (path) =>
        typeof path !== "string" ||
        !isAbsolute(path) ||
        normalize(path) !== path ||
        path.includes("\0")
    ) ||
    !Number.isSafeInteger(value.expectedOwnerUid) ||
    value.expectedOwnerUid < 0 ||
    (value.clock !== undefined && typeof value.clock !== "function")
  ) {
    malformed();
  }
  return Object.freeze({ ...value, clock: value.clock ?? Date.now });
}

function decodeAndVerifyEnvelope(
  envelope: Buffer,
  options: CapturedProvisionOptions,
  enforceFreshness: boolean
): DecodedEnvelope {
  if (
    envelope.byteLength < 6 ||
    envelope.byteLength > DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_REQUEST_BYTES
  ) {
    malformed();
  }
  const headerLength = envelope.readUInt32BE(0);
  if (
    headerLength < 2 ||
    headerLength > HEADER_MAX_BYTES ||
    4 + headerLength >= envelope.byteLength
  ) {
    malformed();
  }
  const headerBytes = Buffer.from(envelope.subarray(4, 4 + headerLength));
  let header: DaytonaAssignmentBootstrapHeader;
  try {
    const headerText = new TextDecoder("utf-8", { fatal: true }).decode(headerBytes);
    header = snapshotHeader(JSON.parse(headerText));
    if (canonicalRuntimeJson(header) !== headerText) malformed();
  } catch {
    malformed();
  } finally {
    headerBytes.fill(0);
  }
  const observationOffset = 4 + headerLength;
  const observationEnd = observationOffset + header.sections[0].bytes;
  const effectEnforcerEnd = observationEnd + header.sections[1].bytes;
  if (
    observationEnd <= observationOffset ||
    effectEnforcerEnd <= observationEnd ||
    effectEnforcerEnd !== envelope.byteLength
  ) {
    malformed();
  }
  const observationPrivateKey = Buffer.from(envelope.subarray(observationOffset, observationEnd));
  const effectEnforcerPrivateKey = Buffer.from(
    envelope.subarray(observationEnd, effectEnforcerEnd)
  );
  try {
    if (
      !sameDigest(rawSha256(observationPrivateKey), header.sections[0].sha256) ||
      !sameDigest(rawSha256(effectEnforcerPrivateKey), header.sections[1].sha256)
    ) {
      malformed();
    }
    assertObservationPrivateKeyMatchesBootstrap(header.bootstrap, observationPrivateKey);
    effectEnforcerIdentity(header.bootstrap, effectEnforcerPrivateKey);
    verifyBootstrapAuthority(header, options, enforceFreshness);
    return Object.freeze({
      header,
      observationPrivateKey,
      effectEnforcerPrivateKey,
    });
  } catch (error) {
    observationPrivateKey.fill(0);
    effectEnforcerPrivateKey.fill(0);
    throw error;
  }
}

function snapshotHeader(value: unknown): DaytonaAssignmentBootstrapHeader {
  const record = exactRecord(value, ["version", "kind", "bootstrap", "sections", "authority"]);
  if (
    field(record, "version") !== 1 ||
    field(record, "kind") !== DAYTONA_ASSIGNMENT_BOOTSTRAP_KIND
  ) {
    malformed();
  }
  const sections = field(record, "sections");
  if (!Array.isArray(sections) || sections.length !== 2) malformed();
  const first = snapshotSection(sections[0], OBSERVATION_SECTION);
  const second = snapshotSection(sections[1], EFFECT_ENFORCER_SECTION);
  const authority = exactRecord(field(record, "authority"), [
    "issuer",
    "issuerKeyId",
    "audience",
    "capability",
    "claimsDigest",
    "issuedAtMs",
    "expiresAtMs",
    "signature",
  ]);
  if (
    field(authority, "issuer") !== AUTHORITY_ISSUER ||
    field(authority, "audience") !== AUTHORITY_AUDIENCE ||
    field(authority, "capability") !== AUTHORITY_CAPABILITY
  ) {
    malformed();
  }
  const signature = field(authority, "signature");
  if (typeof signature !== "string" || !SIGNATURE.test(signature)) malformed();
  const bootstrap = snapshotDaytonaSupervisorBootstrapConfiguration(field(record, "bootstrap"));
  observationIssuerKeyId(bootstrap.assignment.plan.observation.issuerKeyId);
  return Object.freeze({
    version: 1,
    kind: DAYTONA_ASSIGNMENT_BOOTSTRAP_KIND,
    bootstrap,
    sections: Object.freeze([first, second] as const),
    authority: Object.freeze({
      issuer: AUTHORITY_ISSUER,
      issuerKeyId: safeReference(field(authority, "issuerKeyId")),
      audience: AUTHORITY_AUDIENCE,
      capability: AUTHORITY_CAPABILITY,
      claimsDigest: digest(field(authority, "claimsDigest")),
      issuedAtMs: nonNegativeInteger(field(authority, "issuedAtMs")),
      expiresAtMs: positiveInteger(field(authority, "expiresAtMs")),
      signature,
    }),
  });
}

function snapshotSection<Kind extends typeof OBSERVATION_SECTION | typeof EFFECT_ENFORCER_SECTION>(
  value: unknown,
  expectedKind: Kind
): Readonly<{ kind: Kind; bytes: number; sha256: string }> {
  const record = exactRecord(value, ["kind", "bytes", "sha256"]);
  if (field(record, "kind") !== expectedKind) malformed();
  const bytes = positiveInteger(field(record, "bytes"));
  if (bytes > PRIVATE_KEY_MAX_BYTES) malformed();
  return Object.freeze({ kind: expectedKind, bytes, sha256: digest(field(record, "sha256")) });
}

function verifyBootstrapAuthority(
  header: DaytonaAssignmentBootstrapHeader,
  options: CapturedProvisionOptions,
  enforceFreshness: boolean
): void {
  const pin = readAuthorityPin(options.authorityPinFile, options.expectedOwnerUid);
  const now = sampleClock(options.clock);
  const authority = header.authority;
  if (
    authority.issuerKeyId !== pin.issuerKeyId ||
    (enforceFreshness && (now < authority.issuedAtMs || now >= authority.expiresAtMs)) ||
    authority.expiresAtMs <= authority.issuedAtMs ||
    authority.expiresAtMs - authority.issuedAtMs > MAX_AUTHORITY_TTL_MS
  ) {
    malformed();
  }
  const claims = Object.freeze({
    version: header.version,
    kind: header.kind,
    bootstrap: header.bootstrap,
    sections: header.sections,
  });
  const claimsDigest = digestCanonical(DAYTONA_ASSIGNMENT_BOOTSTRAP_CLAIMS_DIGEST_DOMAIN, claims);
  if (!sameDigest(claimsDigest, authority.claimsDigest)) malformed();
  const statement = Object.freeze({
    version: 1,
    issuer: authority.issuer,
    issuerKeyId: authority.issuerKeyId,
    audience: authority.audience,
    capability: authority.capability,
    claimsDigest: authority.claimsDigest,
    issuedAtMs: authority.issuedAtMs,
    expiresAtMs: authority.expiresAtMs,
  });
  const valid = verifyEd25519(
    null,
    Buffer.from(
      `${DAYTONA_ASSIGNMENT_BOOTSTRAP_AUTHORITY_SIGNATURE_DOMAIN}${canonicalRuntimeJson(statement)}`,
      "utf8"
    ),
    pin.publicKey,
    Buffer.from(authority.signature, "base64url")
  );
  if (!valid) malformed();
}

function validateProductionBootstrap(
  bootstrap: DaytonaSupervisorBootstrapConfiguration,
  options: CapturedProvisionOptions
): void {
  const assignmentDirectory = join(options.runtimeRoot, "assignment");
  const expectedStateDirectory = join(
    options.stateRoot,
    bindingDigest(bootstrap.assignment.plan.binding)
  );
  if (
    bootstrap.observation.provisioningRecordFile !==
      join(assignmentDirectory, "observation-provisioning.json") ||
    bootstrap.state.signingPrivateKeyFile !== join(assignmentDirectory, "state-signing.pk8") ||
    bootstrap.state.verificationPublicKeyFile !==
      join(assignmentDirectory, "state-verification.pem") ||
    bootstrap.state.stateDirectory !== expectedStateDirectory ||
    bootstrap.isolation.attestationFile !==
      join(options.runtimeRoot, "live", "isolation-attestation.json") ||
    bootstrap.transport.socketDirectory !== options.runtimeRoot ||
    bootstrap.transport.socketPath !== options.expectedSupervisorSocket ||
    bootstrap.transport.peerCredentialExecutableRoot !==
      dirname(options.expectedPeerCredentialExecutable) ||
    bootstrap.transport.peerCredentialExecutableFile !== options.expectedPeerCredentialExecutable ||
    bootstrap.effect.executableFile !== options.expectedEffectExecutable ||
    bootstrap.effect.executableRoot !== dirname(options.expectedEffectExecutable)
  ) {
    malformed();
  }
  const providerSandboxId = bootstrap.assignment.providerSandboxId;
  if (!UUID_V4.test(providerSandboxId)) malformed();
  const hostname = readBoundedText(options.hostnameFile, 256).trim();
  if (
    hostname !== TERMINALX_SANDBOX_HOSTNAME ||
    process.env.DAYTONA_SANDBOX_ID !== providerSandboxId ||
    process.env.DAYTONA_SANDBOX_USER !== "terminalx"
  ) {
    malformed();
  }
}

function validateImageOwnedPins(
  bootstrap: DaytonaSupervisorBootstrapConfiguration,
  options: CapturedProvisionOptions
): void {
  const value = readPrivateJson(options.imageTrustPinFile, options.expectedOwnerUid, 256 * 1024);
  const pins = exactRecord(value, [
    "version",
    "kind",
    "supervisorArtifactDigest",
    "peerCredentialExecutableSha256",
    "effectExecutableSha256",
    "nodeExecutableSha256",
    "isolationIssuerKeyId",
    "isolationIssuerPublicKeySpkiPem",
    "hardenedDaytonaSourceCommit",
    "effectManifestAuthorityIssuerKeyId",
    "effectManifestAuthorityPublicKeySpkiPem",
    "deploymentBindingIssuerKeyId",
    "deploymentBindingIssuerPublicKeySpkiPem",
  ]);
  if (
    field(pins, "version") !== 1 ||
    field(pins, "kind") !== "terminalx.daytona-sandbox-trust-pins"
  ) {
    malformed();
  }
  const isolationPublicKey = canonicalPublicKeyPem(field(pins, "isolationIssuerPublicKeySpkiPem"));
  const deploymentBindingPublicKeyPem = canonicalPublicKeyPem(
    field(pins, "deploymentBindingIssuerPublicKeySpkiPem")
  );
  const effectManifestAuthorityIssuerKeyId = safeReference(
    field(pins, "effectManifestAuthorityIssuerKeyId")
  );
  const effectManifestAuthorityPublicKeySpkiPem = canonicalPublicKeyPem(
    field(pins, "effectManifestAuthorityPublicKeySpkiPem")
  );
  const effectManifestAuthorityPublicKeySpkiDer = createPublicKey(
    effectManifestAuthorityPublicKeySpkiPem
  ).export({ type: "spki", format: "der" });
  const effectManifestAuthorityPublicKeySpkiDigest = rawSha256(
    effectManifestAuthorityPublicKeySpkiDer
  );
  const manifestAuthorityPins = Object.freeze([
    Object.freeze({
      issuerKeyId: effectManifestAuthorityIssuerKeyId,
      publicKeySpkiPem: effectManifestAuthorityPublicKeySpkiPem,
      publicKeySpkiDigest: effectManifestAuthorityPublicKeySpkiDigest,
    }),
  ]);
  const nodeExecutableSha256 = digest(field(pins, "nodeExecutableSha256"));
  if (
    !sameDigest(
      bootstrap.assignment.supervisorArtifactDigest,
      digest(field(pins, "supervisorArtifactDigest"))
    ) ||
    !sameDigest(
      bootstrap.transport.peerCredentialExecutableSha256,
      digest(field(pins, "peerCredentialExecutableSha256"))
    ) ||
    !sameDigest(bootstrap.effect.executableSha256, digest(field(pins, "effectExecutableSha256"))) ||
    bootstrap.isolation.issuerKeyId !== safeReference(field(pins, "isolationIssuerKeyId")) ||
    bootstrap.isolation.issuerPublicKeySpkiPem !== isolationPublicKey ||
    bootstrap.isolation.hardenedDaytonaSourceCommit !==
      safeReference(field(pins, "hardenedDaytonaSourceCommit")) ||
    canonicalRuntimeJson(bootstrap.effect.pinnedManifestAuthorityPublicKeys) !==
      canonicalRuntimeJson(manifestAuthorityPins)
  ) {
    malformed();
  }
  try {
    const registry = createRuntimeEffectEnforcerTrustRegistry({
      manifest: bootstrap.effect.manifest,
      attestations: Object.freeze([]),
      pinnedManifestAuthorityPublicKeys: manifestAuthorityPins,
    });
    const effectRecord = verifyDaytonaAssignmentEffectManifestBinding({
      manifest: registry.manifest,
      plan: bootstrap.assignment.plan,
      providerSandboxId: bootstrap.assignment.providerSandboxId,
      providerRevision: bootstrap.assignment.expectedRevision,
      nowMs: sampleClock(options.clock),
    });
    if (
      !sameDigest(registry.manifestDigest, bootstrap.assignment.effectEnforcerSetDigest) ||
      !sameDigest(
        effectRecord.activation.effectEnforcerSetDigest,
        bootstrap.assignment.effectEnforcerSetDigest
      ) ||
      !sameDigest(
        effectRecord.activation.effectEnforcerPolicyDigest,
        bootstrap.assignment.plan.effectEnforcerPolicyDigest
      )
    ) {
      malformed();
    }
  } catch (error) {
    if (error instanceof DaytonaAssignmentBootstrapError) throw error;
    malformed();
  }
  validateDeploymentBinding(
    bootstrap,
    options,
    safeReference(field(pins, "deploymentBindingIssuerKeyId")),
    deploymentBindingPublicKeyPem
  );
  assertPinnedRootExecutable({
    executableRoot: dirname(options.expectedPeerCredentialExecutable),
    executableFile: options.expectedPeerCredentialExecutable,
    executableSha256: bootstrap.transport.peerCredentialExecutableSha256,
    expectedOwnerUid: options.expectedOwnerUid,
  });
  assertPinnedRootExecutable({
    executableRoot: dirname(options.expectedEffectExecutable),
    executableFile: options.expectedEffectExecutable,
    executableSha256: bootstrap.effect.executableSha256,
    expectedOwnerUid: options.expectedOwnerUid,
  });
  assertPinnedRootExecutable({
    executableRoot: dirname(options.expectedNodeExecutable),
    executableFile: options.expectedNodeExecutable,
    executableSha256: nodeExecutableSha256,
    expectedOwnerUid: options.expectedOwnerUid,
  });
}

function validateDeploymentBinding(
  bootstrap: DaytonaSupervisorBootstrapConfiguration,
  options: CapturedProvisionOptions,
  expectedIssuerKeyId: string,
  issuerPublicKeySpkiPem: string
): void {
  const binding = exactRecord(
    readPrivateJson(options.deploymentBindingFile, options.expectedOwnerUid, 128 * 1024, false),
    [
      "version",
      "kind",
      "providerSandboxId",
      "providerRevision",
      "sandboxArtifactDigest",
      "expectedSandboxImageId",
      "expectedSandboxSnapshotRef",
      "authority",
    ]
  );
  if (
    field(binding, "version") !== 1 ||
    field(binding, "kind") !== DAYTONA_SANDBOX_DEPLOYMENT_BINDING_KIND
  ) {
    malformed();
  }
  const claims = Object.freeze({
    version: 1 as const,
    kind: DAYTONA_SANDBOX_DEPLOYMENT_BINDING_KIND,
    providerSandboxId: safeReference(field(binding, "providerSandboxId")),
    providerRevision: positiveInteger(field(binding, "providerRevision")),
    sandboxArtifactDigest: digest(field(binding, "sandboxArtifactDigest")),
    expectedSandboxImageId: safeReference(field(binding, "expectedSandboxImageId")),
    expectedSandboxSnapshotRef: safeReference(field(binding, "expectedSandboxSnapshotRef")),
  });
  const authority = exactRecord(field(binding, "authority"), [
    "issuer",
    "issuerKeyId",
    "audience",
    "capability",
    "claimsDigest",
    "issuedAtMs",
    "expiresAtMs",
    "signature",
  ]);
  const signature = field(authority, "signature");
  if (
    field(authority, "issuer") !== DEPLOYMENT_BINDING_ISSUER ||
    field(authority, "audience") !== DEPLOYMENT_BINDING_AUDIENCE ||
    field(authority, "capability") !== DEPLOYMENT_BINDING_CAPABILITY ||
    field(authority, "issuerKeyId") !== expectedIssuerKeyId ||
    typeof signature !== "string" ||
    !SIGNATURE.test(signature)
  ) {
    malformed();
  }
  const claimsDigest = digestCanonical(
    DAYTONA_SANDBOX_DEPLOYMENT_BINDING_CLAIMS_DIGEST_DOMAIN,
    claims
  );
  const issuedAtMs = nonNegativeInteger(field(authority, "issuedAtMs"));
  const expiresAtMs = positiveInteger(field(authority, "expiresAtMs"));
  const now = sampleClock(options.clock);
  if (
    !sameDigest(claimsDigest, digest(field(authority, "claimsDigest"))) ||
    now < issuedAtMs ||
    now >= expiresAtMs ||
    expiresAtMs <= issuedAtMs ||
    expiresAtMs - issuedAtMs > MAX_DEPLOYMENT_BINDING_TTL_MS ||
    claims.providerSandboxId !== bootstrap.assignment.providerSandboxId ||
    claims.providerRevision !== bootstrap.assignment.expectedRevision ||
    !sameDigest(claims.sandboxArtifactDigest, bootstrap.assignment.artifactDigest) ||
    claims.expectedSandboxImageId !== bootstrap.isolation.expectedSandboxImageId ||
    claims.expectedSandboxSnapshotRef !== bootstrap.isolation.expectedSandboxSnapshotRef
  ) {
    malformed();
  }
  const statement = Object.freeze({
    version: 1,
    issuer: DEPLOYMENT_BINDING_ISSUER,
    issuerKeyId: expectedIssuerKeyId,
    audience: DEPLOYMENT_BINDING_AUDIENCE,
    capability: DEPLOYMENT_BINDING_CAPABILITY,
    claimsDigest,
    issuedAtMs,
    expiresAtMs,
  });
  const valid = verifyEd25519(
    null,
    Buffer.from(
      `${DAYTONA_SANDBOX_DEPLOYMENT_BINDING_SIGNATURE_DOMAIN}${canonicalRuntimeJson(statement)}`,
      "utf8"
    ),
    createPublicKey(issuerPublicKeySpkiPem),
    Buffer.from(signature, "base64url")
  );
  if (!valid) malformed();
}

function installAssignment(
  decoded: DecodedEnvelope,
  envelopeDigest: string,
  options: CapturedProvisionOptions
): void {
  const temporary = join(options.runtimeRoot, `.assignment-${randomBytes(12).toString("hex")}`);
  const final = join(options.runtimeRoot, "assignment");
  mkdirSync(temporary, { mode: 0o700 });
  chmodSync(temporary, 0o700);
  try {
    const bootstrap = decoded.header.bootstrap;
    writePrivateJson(join(temporary, "bootstrap.json"), bootstrap);
    writePrivateFile(join(temporary, "observation-key.pk8"), decoded.observationPrivateKey);
    const observationProvisioning = observationProvisioningRecord(bootstrap, final);
    writePrivateJson(join(temporary, "observation-provisioning.json"), observationProvisioning);
    const effectIdentity = effectEnforcerIdentity(bootstrap, decoded.effectEnforcerPrivateKey);
    writePrivateFile(join(temporary, "effect-enforcer-key.pk8"), decoded.effectEnforcerPrivateKey);
    writePrivateJson(
      join(temporary, "effect-enforcer-provisioning.json"),
      effectEnforcerProvisioningRecord(bootstrap, effectIdentity, final)
    );
    const stateKeys = generateKeyPairSync("ed25519");
    const statePrivateDer = stateKeys.privateKey.export({ type: "pkcs8", format: "der" });
    const statePrivateBytes = Buffer.isBuffer(statePrivateDer)
      ? statePrivateDer
      : Buffer.from(statePrivateDer);
    const statePublicPem = String(stateKeys.publicKey.export({ type: "spki", format: "pem" }));
    const statePublicBytes = Buffer.from(statePublicPem, "utf8");
    try {
      writePrivateFile(join(temporary, "state-signing.pk8"), statePrivateBytes);
      writePrivateFile(join(temporary, "state-verification.pem"), statePublicBytes);
    } finally {
      statePrivateBytes.fill(0);
      statePublicBytes.fill(0);
    }
    writePrivateJson(
      join(temporary, "provisioning-metadata.json"),
      Object.freeze({
        version: 1,
        kind: "terminalx.daytona-assignment-provisioning-metadata",
        envelopeDigest,
      })
    );
    mkdirPrivateStateDirectory(bootstrap.state.stateDirectory, options.expectedOwnerUid);
    renameSync(temporary, final);
    fsyncDirectory(options.runtimeRoot);
  } catch (error) {
    removeKnownTemporaryFiles(temporary);
    throw error;
  }
}

function installedDescriptor(
  header: DaytonaAssignmentBootstrapHeader,
  envelopeDigest: string,
  runtimeRoot: string,
  stateVerificationPublicKeySpkiPem: string,
  effectIdentity: EffectEnforcerIdentity
): DaytonaAssignmentBootstrapInstalledDescriptor {
  const bootstrap = header.bootstrap;
  const plan = bootstrap.assignment.plan;
  return Object.freeze({
    version: 1,
    kind: DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_KIND,
    envelopeDigest,
    providerIdentityCommitment: digestText(
      PROVIDER_IDENTITY_DIGEST_DOMAIN,
      bootstrap.assignment.providerSandboxId
    ),
    providerRevision: bootstrap.assignment.expectedRevision,
    planDigest: digestCanonical(HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN, plan),
    assignmentPlanDigest: digestCanonical(HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN, plan),
    effectEnforcerPolicyDigest: plan.effectEnforcerPolicyDigest,
    effectManifestBindingDigest: snapshotRuntimeEffectEnforcerManifest(bootstrap.effect.manifest)
      .effectManifestBindingDigest,
    effectEnforcerSetDigest: bootstrap.assignment.effectEnforcerSetDigest,
    bindingDigest: bindingDigest(plan.binding),
    observationIssuerKeyId: plan.observation.issuerKeyId,
    observationPublicKeyDigest: rawSha256(Buffer.from(plan.observation.publicKeySpkiPem, "utf8")),
    effectEnforcerKeyId: effectIdentity.enforcerKeyId,
    effectEnforcerPublicKeyDigest: effectIdentity.publicKeySpkiDigest,
    stateVerificationPublicKeySpkiPem,
    stateVerificationPublicKeyDigest: rawSha256(
      Buffer.from(stateVerificationPublicKeySpkiPem, "utf8")
    ),
    supervisorArtifactDigest: bootstrap.assignment.supervisorArtifactDigest,
    installedMarker:
      runtimeRoot === "/run/terminalx-root"
        ? DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_MARKER
        : `${runtimeRoot}/assignment.installed.json`,
    supervisorReady: false,
  });
}

function assertObservationPrivateKeyMatchesBootstrap(
  bootstrap: DaytonaSupervisorBootstrapConfiguration,
  observationPrivateKeyBytes: Buffer
): void {
  const observation = parseCanonicalPrivateKey(observationPrivateKeyBytes);
  const actualObservation = createPublicKey(observation).export({ type: "spki", format: "pem" });
  if (actualObservation !== bootstrap.assignment.plan.observation.publicKeySpkiPem) malformed();
}

interface EffectEnforcerIdentity {
  readonly enforcerRef: string;
  readonly enforcerKeyId: string;
  readonly publicKeySpkiDigest: string;
}

function effectEnforcerProvisioningRecord(
  bootstrap: DaytonaSupervisorBootstrapConfiguration,
  identity: EffectEnforcerIdentity,
  assignmentDirectory: string
): unknown {
  const manifest = snapshotRuntimeEffectEnforcerManifest(bootstrap.effect.manifest);
  const assignmentPlanDigest = digestCanonical(
    HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN,
    bootstrap.assignment.plan
  );
  return Object.freeze({
    version: 1,
    kind: "terminalx.daytona-effect-enforcer-provisioning",
    enforcerRef: identity.enforcerRef,
    enforcerKeyId: identity.enforcerKeyId,
    publicKeySpkiDigest: identity.publicKeySpkiDigest,
    assignmentPlanDigest,
    effectEnforcerPolicyDigest: bootstrap.assignment.plan.effectEnforcerPolicyDigest,
    providerIdentityCommitment: digestText(
      PROVIDER_IDENTITY_DIGEST_DOMAIN,
      bootstrap.assignment.providerSandboxId
    ),
    providerRevision: bootstrap.assignment.expectedRevision,
    effectManifestBindingDigest: manifest.effectManifestBindingDigest,
    effectEnforcerSetDigest: bootstrap.assignment.effectEnforcerSetDigest,
    privateKeyFile: join(assignmentDirectory, "effect-enforcer-key.pk8"),
  });
}

function effectEnforcerIdentity(
  bootstrap: DaytonaSupervisorBootstrapConfiguration,
  privateKeyBytes: Buffer
): EffectEnforcerIdentity {
  try {
    const privateKey = parseCanonicalPrivateKey(privateKeyBytes);
    const publicKey = createPublicKey(privateKey);
    const publicKeySpkiPem = String(publicKey.export({ type: "spki", format: "pem" }));
    const publicKeySpkiDer = publicKey.export({ type: "spki", format: "der" });
    const publicKeySpkiDigest = rawSha256(publicKeySpkiDer);
    const manifest = snapshotRuntimeEffectEnforcerManifest(bootstrap.effect.manifest);
    if (
      !sameDigest(manifest.authority.claimsDigest, bootstrap.assignment.effectEnforcerSetDigest)
    ) {
      malformed();
    }
    const matches = manifest.enforcers.filter(
      (entry) =>
        entry.publicKeySpkiPem === publicKeySpkiPem &&
        sameDigest(entry.publicKeySpkiDigest, publicKeySpkiDigest)
    );
    const entry = matches[0];
    if (
      matches.length !== 1 ||
      !entry ||
      entry.enforcerKind !== "runtime" ||
      canonicalRuntimeJson(entry.allowedPurposes) !==
        canonicalRuntimeJson(["runtime-lifecycle", "stale-lifecycle-effect-containment"])
    ) {
      malformed();
    }
    return Object.freeze({
      enforcerRef: safeReference(entry.enforcerRef),
      enforcerKeyId: safeReference(entry.enforcerKeyId),
      publicKeySpkiDigest,
    });
  } catch (error) {
    if (error instanceof DaytonaAssignmentBootstrapError) throw error;
    malformed();
  }
}

function parseCanonicalPrivateKey(bytes: Buffer): KeyObject {
  try {
    const key = createPrivateKey({ key: bytes, format: "der", type: "pkcs8" });
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") malformed();
    const canonical = key.export({ type: "pkcs8", format: "der" });
    const canonicalBytes = Buffer.isBuffer(canonical) ? canonical : Buffer.from(canonical);
    try {
      if (
        canonicalBytes.byteLength !== bytes.byteLength ||
        !timingSafeEqual(canonicalBytes, bytes)
      ) {
        malformed();
      }
    } finally {
      canonicalBytes.fill(0);
    }
    return key;
  } catch (error) {
    if (error instanceof DaytonaAssignmentBootstrapError) throw error;
    malformed();
  }
}

function readAuthorityPin(
  path: string,
  expectedOwnerUid: number
): {
  readonly issuerKeyId: string;
  readonly publicKey: KeyObject;
} {
  const value = readPrivateJson(path, expectedOwnerUid, 64 * 1024);
  const record = exactRecord(value, ["version", "kind", "issuerKeyId", "publicKeySpkiPem"]);
  if (
    field(record, "version") !== 1 ||
    field(record, "kind") !== "terminalx.daytona-bootstrap-authority-pin"
  ) {
    malformed();
  }
  const publicKeyPem = field(record, "publicKeySpkiPem");
  if (typeof publicKeyPem !== "string") malformed();
  const publicKey = createPublicKey(publicKeyPem);
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") malformed();
  const canonical = publicKey.export({ type: "spki", format: "pem" });
  if (canonical !== publicKeyPem) malformed();
  return Object.freeze({
    issuerKeyId: safeReference(field(record, "issuerKeyId")),
    publicKey,
  });
}

function observationProvisioningRecord(
  bootstrap: DaytonaSupervisorBootstrapConfiguration,
  assignmentDirectory: string
): unknown {
  return Object.freeze({
    version: 1,
    kind: "terminalx.daytona-observation-key-provisioning",
    keyProvisioningRef: bootstrap.assignment.plan.observation.keyProvisioningRef,
    binding: bootstrap.assignment.plan.binding,
    issuerKeyId: bootstrap.assignment.plan.observation.issuerKeyId,
    publicKeySpkiPem: bootstrap.assignment.plan.observation.publicKeySpkiPem,
    privateKeyFile: join(assignmentDirectory, "observation-key.pk8"),
  });
}

function validateInstalledAssignment(
  decoded: DecodedEnvelope,
  envelopeDigest: string,
  options: CapturedProvisionOptions
): DaytonaAssignmentBootstrapInstalledDescriptor {
  const directory = join(options.runtimeRoot, "assignment");
  assertPrivateDirectory(directory, options.expectedOwnerUid);
  const expectedFiles = Object.freeze([
    "bootstrap.json",
    "effect-enforcer-key.pk8",
    "effect-enforcer-provisioning.json",
    "observation-key.pk8",
    "observation-provisioning.json",
    "provisioning-metadata.json",
    "state-signing.pk8",
    "state-verification.pem",
  ]);
  const actualFiles = readdirSync(directory).sort();
  if (
    actualFiles.length !== expectedFiles.length ||
    actualFiles.some((name, index) => name !== [...expectedFiles].sort()[index])
  ) {
    unavailable();
  }
  const metadata = readProvisioningMetadata(
    join(directory, "provisioning-metadata.json"),
    options.expectedOwnerUid
  );
  if (!sameDigest(metadata.envelopeDigest, envelopeDigest)) conflict();
  if (
    canonicalRuntimeJson(
      readPrivateJson(join(directory, "bootstrap.json"), options.expectedOwnerUid, HEADER_MAX_BYTES)
    ) !== canonicalRuntimeJson(decoded.header.bootstrap) ||
    canonicalRuntimeJson(
      readPrivateJson(
        join(directory, "observation-provisioning.json"),
        options.expectedOwnerUid,
        HEADER_MAX_BYTES
      )
    ) !== canonicalRuntimeJson(observationProvisioningRecord(decoded.header.bootstrap, directory))
  ) {
    unavailable();
  }
  const observationBytes = readPrivateBytes(
    join(directory, "observation-key.pk8"),
    options.expectedOwnerUid,
    PRIVATE_KEY_MAX_BYTES
  );
  try {
    if (
      !sameDigest(rawSha256(observationBytes), decoded.header.sections[0].sha256) ||
      observationBytes.byteLength !== decoded.observationPrivateKey.byteLength ||
      !timingSafeEqual(observationBytes, decoded.observationPrivateKey)
    ) {
      unavailable();
    }
    assertObservationPrivateKeyMatchesBootstrap(decoded.header.bootstrap, observationBytes);
  } finally {
    observationBytes.fill(0);
  }
  const effectEnforcerBytes = readPrivateBytes(
    join(directory, "effect-enforcer-key.pk8"),
    options.expectedOwnerUid,
    PRIVATE_KEY_MAX_BYTES
  );
  let effectIdentity: EffectEnforcerIdentity;
  try {
    if (
      !sameDigest(rawSha256(effectEnforcerBytes), decoded.header.sections[1].sha256) ||
      effectEnforcerBytes.byteLength !== decoded.effectEnforcerPrivateKey.byteLength ||
      !timingSafeEqual(effectEnforcerBytes, decoded.effectEnforcerPrivateKey)
    ) {
      unavailable();
    }
    effectIdentity = effectEnforcerIdentity(decoded.header.bootstrap, effectEnforcerBytes);
    const expectedProvisioning = effectEnforcerProvisioningRecord(
      decoded.header.bootstrap,
      effectIdentity,
      directory
    );
    if (
      canonicalRuntimeJson(
        readPrivateJson(
          join(directory, "effect-enforcer-provisioning.json"),
          options.expectedOwnerUid,
          HEADER_MAX_BYTES
        )
      ) !== canonicalRuntimeJson(expectedProvisioning)
    ) {
      unavailable();
    }
  } finally {
    effectEnforcerBytes.fill(0);
  }
  const statePrivateBytes = readPrivateBytes(
    join(directory, "state-signing.pk8"),
    options.expectedOwnerUid,
    PRIVATE_KEY_MAX_BYTES
  );
  let derivedStatePublicPem: string;
  try {
    const statePrivateKey = parseCanonicalPrivateKey(statePrivateBytes);
    derivedStatePublicPem = String(
      createPublicKey(statePrivateKey).export({ type: "spki", format: "pem" })
    );
  } finally {
    statePrivateBytes.fill(0);
  }
  const statePublicBytes = readPrivateBytes(
    join(directory, "state-verification.pem"),
    options.expectedOwnerUid,
    PRIVATE_KEY_MAX_BYTES
  );
  try {
    const installedStatePublicPem = canonicalPublicKeyPem(statePublicBytes.toString("utf8"));
    if (installedStatePublicPem !== derivedStatePublicPem) unavailable();
  } finally {
    statePublicBytes.fill(0);
  }
  assertPrivateDirectory(decoded.header.bootstrap.state.stateDirectory, options.expectedOwnerUid);
  return installedDescriptor(
    decoded.header,
    envelopeDigest,
    options.runtimeRoot,
    derivedStatePublicPem,
    effectIdentity
  );
}

function writeInstalledMarker(
  path: string,
  descriptor: DaytonaAssignmentBootstrapInstalledDescriptor,
  runtimeRoot: string
): void {
  if (existsSync(path)) conflict();
  const temporary = join(runtimeRoot, `.assignment-installed-${randomBytes(12).toString("hex")}`);
  writePrivateJson(temporary, descriptor);
  renameSync(temporary, path);
  fsyncDirectory(runtimeRoot);
}

function readInstalledDescriptor(
  path: string,
  expectedOwnerUid: number
): DaytonaAssignmentBootstrapInstalledDescriptor {
  return snapshotDaytonaAssignmentBootstrapInstalledDescriptor(
    readPrivateJson(path, expectedOwnerUid, DAYTONA_ASSIGNMENT_BOOTSTRAP_MAX_RESPONSE_BYTES)
  );
}

export function snapshotDaytonaAssignmentBootstrapInstalledDescriptor(
  value: unknown
): DaytonaAssignmentBootstrapInstalledDescriptor {
  const record = exactRecord(value, [
    "version",
    "kind",
    "envelopeDigest",
    "providerIdentityCommitment",
    "providerRevision",
    "planDigest",
    "assignmentPlanDigest",
    "effectEnforcerPolicyDigest",
    "effectManifestBindingDigest",
    "effectEnforcerSetDigest",
    "bindingDigest",
    "observationIssuerKeyId",
    "observationPublicKeyDigest",
    "effectEnforcerKeyId",
    "effectEnforcerPublicKeyDigest",
    "stateVerificationPublicKeySpkiPem",
    "stateVerificationPublicKeyDigest",
    "supervisorArtifactDigest",
    "installedMarker",
    "supervisorReady",
  ]);
  if (
    field(record, "version") !== 1 ||
    field(record, "kind") !== DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_KIND ||
    field(record, "supervisorReady") !== false
  ) {
    conflict();
  }
  const stateVerificationPublicKeySpkiPem = canonicalPublicKeyPem(
    field(record, "stateVerificationPublicKeySpkiPem")
  );
  const stateVerificationPublicKeyDigest = digest(
    field(record, "stateVerificationPublicKeyDigest")
  );
  if (
    !sameDigest(
      stateVerificationPublicKeyDigest,
      rawSha256(Buffer.from(stateVerificationPublicKeySpkiPem, "utf8"))
    )
  ) {
    conflict();
  }
  const planDigest = digest(field(record, "planDigest"));
  const assignmentPlanDigest = digest(field(record, "assignmentPlanDigest"));
  if (!sameDigest(planDigest, assignmentPlanDigest)) conflict();
  return Object.freeze({
    version: 1,
    kind: DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_KIND,
    envelopeDigest: digest(field(record, "envelopeDigest")),
    providerIdentityCommitment: digest(field(record, "providerIdentityCommitment")),
    providerRevision: positiveInteger(field(record, "providerRevision")),
    planDigest,
    assignmentPlanDigest,
    effectEnforcerPolicyDigest: digest(field(record, "effectEnforcerPolicyDigest")),
    effectManifestBindingDigest: digest(field(record, "effectManifestBindingDigest")),
    effectEnforcerSetDigest: digest(field(record, "effectEnforcerSetDigest")),
    bindingDigest: digest(field(record, "bindingDigest")),
    observationIssuerKeyId: observationIssuerKeyId(field(record, "observationIssuerKeyId")),
    observationPublicKeyDigest: digest(field(record, "observationPublicKeyDigest")),
    effectEnforcerKeyId: safeReference(field(record, "effectEnforcerKeyId")),
    effectEnforcerPublicKeyDigest: digest(field(record, "effectEnforcerPublicKeyDigest")),
    stateVerificationPublicKeySpkiPem,
    stateVerificationPublicKeyDigest,
    supervisorArtifactDigest: digest(field(record, "supervisorArtifactDigest")),
    installedMarker: safeReference(field(record, "installedMarker")),
    supervisorReady: false,
  });
}

function readProvisioningMetadata(
  path: string,
  expectedOwnerUid: number
): { envelopeDigest: string } {
  const record = exactRecord(readPrivateJson(path, expectedOwnerUid, 4096), [
    "version",
    "kind",
    "envelopeDigest",
  ]);
  if (
    field(record, "version") !== 1 ||
    field(record, "kind") !== "terminalx.daytona-assignment-provisioning-metadata"
  ) {
    conflict();
  }
  return Object.freeze({ envelopeDigest: digest(field(record, "envelopeDigest")) });
}

function readPrivateJson(
  path: string,
  expectedOwnerUid: number,
  maximumBytes: number,
  trailingNewline = true
): unknown {
  const bytes = readPrivateBytes(path, expectedOwnerUid, maximumBytes);
  try {
    if (bytes.byteLength < 2) malformed();
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (trailingNewline !== text.endsWith("\n")) malformed();
    const json = trailingNewline ? text.slice(0, -1) : text;
    const value = snapshotRuntimeSupervisorPortableData(JSON.parse(json));
    if (canonicalRuntimeJson(value) !== json) malformed();
    return value;
  } catch (error) {
    if (error instanceof DaytonaAssignmentBootstrapError) throw error;
    malformed();
  } finally {
    bytes.fill(0);
  }
}

function readPrivateBytes(path: string, expectedOwnerUid: number, maximumBytes: number): Buffer {
  try {
    const stat = lstatSync(path);
    if (
      realpathSync.native(path) !== path ||
      stat.isSymbolicLink() ||
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.uid !== expectedOwnerUid ||
      (stat.mode & 0o777) !== 0o600 ||
      stat.size < 1 ||
      stat.size > maximumBytes
    ) {
      malformed();
    }
    return readFileSync(path);
  } catch (error) {
    if (error instanceof DaytonaAssignmentBootstrapError) throw error;
    malformed();
  }
}

function readBoundedText(path: string, maximumBytes: number): string {
  const bytes = readFileSync(path);
  try {
    if (bytes.byteLength < 1 || bytes.byteLength > maximumBytes) malformed();
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    if (error instanceof DaytonaAssignmentBootstrapError) throw error;
    malformed();
  } finally {
    bytes.fill(0);
  }
}

function writePrivateJson(path: string, value: unknown): void {
  const bytes = Buffer.from(`${canonicalRuntimeJson(value)}\n`, "utf8");
  try {
    writePrivateFile(path, bytes);
  } finally {
    bytes.fill(0);
  }
}

function writePrivateFile(path: string, bytes: Buffer): void {
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

function mkdirPrivateStateDirectory(path: string, expectedOwnerUid: number): void {
  if (!existsSync(path)) mkdirSync(path, { recursive: false, mode: 0o700 });
  chmodSync(path, 0o700);
  assertPrivateDirectory(path, expectedOwnerUid);
}

function assertPrivateDirectory(path: string, expectedOwnerUid: number): void {
  const stat = lstatSync(path);
  if (
    realpathSync.native(path) !== path ||
    stat.isSymbolicLink() ||
    !stat.isDirectory() ||
    stat.uid !== expectedOwnerUid ||
    (stat.mode & 0o777) !== 0o700
  ) {
    unavailable();
  }
}

function removeKnownTemporaryFiles(directory: string): void {
  if (!existsSync(directory)) return;
  const known = [
    "bootstrap.json",
    "effect-enforcer-key.pk8",
    "effect-enforcer-provisioning.json",
    "observation-key.pk8",
    "observation-provisioning.json",
    "state-signing.pk8",
    "state-verification.pem",
    "provisioning-metadata.json",
  ];
  for (const name of known) {
    const path = join(directory, name);
    if (!existsSync(path)) continue;
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink()) return;
    unlinkSync(path);
  }
  rmdirSync(directory);
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, fsConstants.O_RDONLY | noFollowFlag());
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    malformed();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    malformed();
  }
  for (const name of names) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) malformed();
  return descriptor.value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) malformed();
  return value;
}

function observationIssuerKeyId(value: unknown): string {
  if (typeof value !== "string" || !OBSERVATION_ISSUER_KEY_ID.test(value)) malformed();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) malformed();
  return value;
}

function canonicalPublicKeyPem(value: unknown): string {
  if (typeof value !== "string") malformed();
  try {
    const key = createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") malformed();
    const canonical = key.export({ type: "spki", format: "pem" });
    if (typeof canonical !== "string" || canonical !== value) malformed();
    return value;
  } catch (error) {
    if (error instanceof DaytonaAssignmentBootstrapError) throw error;
    malformed();
  }
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) malformed();
  return value as number;
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) malformed();
  return value as number;
}

function sampleClock(clock: () => number): number {
  const value = clock();
  if (!Number.isSafeInteger(value) || value < 0) unavailable();
  return value;
}

function rawSha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function digestCanonical(domain: string, value: unknown): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalRuntimeJson(value), "utf8")
    .digest("hex");
}

function digestText(domain: string, value: string): string {
  return createHash("sha256").update(domain, "utf8").update(value, "utf8").digest("hex");
}

function digestBytes(domain: string, value: Uint8Array): string {
  return createHash("sha256").update(domain, "utf8").update(value).digest("hex");
}

function bindingDigest(binding: unknown): string {
  return digestCanonical(BINDING_DIGEST_DOMAIN, binding);
}

function sameDigest(left: string, right: string): boolean {
  return (
    SHA256.test(left) &&
    SHA256.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"))
  );
}

function assertEffectiveUid(expectedOwnerUid: number): void {
  if (typeof process.geteuid !== "function" || process.geteuid() !== expectedOwnerUid)
    unavailable();
}

function noFollowFlag(): number {
  return fsConstants.O_NOFOLLOW ?? 0;
}

function malformed(): never {
  throw new DaytonaAssignmentBootstrapError(64);
}

function conflict(): never {
  throw new DaytonaAssignmentBootstrapError(73);
}

function unavailable(): never {
  throw new DaytonaAssignmentBootstrapError(74);
}
