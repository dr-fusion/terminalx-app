import crypto from "node:crypto";

export const CONNECTION_SET_SCHEMA = 1 as const;
export const CHANNEL_BINDING_POLICY_SCHEMA = 1 as const;
export const LINK_CHALLENGE_MIN_TTL_MS = 60 * 1000;
export const LINK_CHALLENGE_MAX_TTL_MS = 10 * 60 * 1000;
export const LINK_CHALLENGE_MAX_AUTH_AGE_MS = 5 * 60 * 1000;
export const LINK_CHALLENGE_MAX_ACTIVE_PER_USER_INSTALLATION = 3;
export const LINK_CHALLENGE_MAX_ACTIVE_PER_INSTALLATION = 128;
export const LINK_CHALLENGE_ISSUANCE_WINDOW_MS = 60 * 60 * 1000;
export const LINK_CHALLENGE_MAX_ISSUED_PER_USER_INSTALLATION_WINDOW = 12;
export const LINK_CHALLENGE_MAX_ISSUED_PER_INSTALLATION_WINDOW = 512;

export type ConnectionProvider = "slack" | "telegram";
export type CredentialBrokerKind = "onepassword-connect" | "oauth-envelope";
export type CredentialHandleUsage = "installation" | "identity-connection";
export type ConnectionStatus = "active" | "revoked";
export type ConversationKind = "channel" | "thread" | "topic";

export interface ConnectionActorSnapshot {
  userId: string;
  userGeneration: number;
  authProvider: "local" | "google" | "password";
  authSubject: string;
  authIdentityGeneration: number;
  authenticatedAtMs?: number;
  credentialIssuedAtMs: number;
  credentialExpiresAtMs: number;
  credentialJtiDigest: string;
  device: { provenance: "browser" } | { provenance: "paired-device"; id: string };
}

export interface CredentialHandleView {
  id: string;
  provider: ConnectionProvider;
  brokerKind: CredentialBrokerKind;
  usage: CredentialHandleUsage;
  /** Domain-separated SHA-256 of the broker-issued, single-use registration receipt. */
  brokerReceiptDigest: string;
  /** Canonical digest of the exact Team/installation or User/identity authority target. */
  authorityBindingDigest: string;
  status: ConnectionStatus;
  generation: number;
  replacesHandleId: string | null;
  replacesGeneration: number | null;
  createdAtMs: number;
  updatedAtMs: number;
  revokedAtMs: number | null;
}

export interface ChannelInstallationView {
  id: string;
  teamId: string;
  provider: ConnectionProvider;
  externalTenantId: string;
  externalAppId: string;
  credentialHandleId: string;
  credentialHandleGeneration: number;
  reviewedScopes: readonly string[];
  reviewedScopesDigest: string;
  capabilities: readonly string[];
  capabilitiesDigest: string;
  status: ConnectionStatus;
  revision: number;
  createdAtMs: number;
  updatedAtMs: number;
  revokedAtMs: number | null;
}

export interface IssuedLinkChallenge {
  /** Returned once to the caller. Only its SHA-256 digest is persisted. */
  challenge: string;
  expiresAtMs: number;
  installationId: string;
  installationRevision: number;
  requestedScopes: readonly string[];
}

export interface IdentityConnectionView {
  id: string;
  userId: string;
  provider: ConnectionProvider;
  externalTenantId: string;
  externalSubject: string;
  installationId: string;
  installationRevision: number;
  scopes: readonly string[];
  scopesDigest: string;
  credentialHandleId: string | null;
  credentialHandleGeneration: number | null;
  status: ConnectionStatus;
  generation: number;
  createdAtMs: number;
  updatedAtMs: number;
  revokedAtMs: number | null;
}

export interface ChannelInboundPolicy {
  mode: "comments-only" | "comments-and-directives" | "notifications-only";
  requireLinkedIdentity: boolean;
}

export interface ChannelOutboundPolicy {
  mode: "disabled" | "mentions" | "all-session-messages";
  allowArtifacts: boolean;
}

export interface ChannelBindingView {
  id: string;
  sessionId: string;
  teamId: string;
  installationId: string;
  installationRevision: number;
  provider: ConnectionProvider;
  conversationKind: ConversationKind;
  externalConversationId: string;
  externalThreadId: string;
  inboundPolicy: ChannelInboundPolicy;
  inboundPolicyDigest: string;
  outboundPolicy: ChannelOutboundPolicy;
  outboundPolicyDigest: string;
  status: ConnectionStatus;
  revision: number;
  createdAtMs: number;
  updatedAtMs: number;
  revokedAtMs: number | null;
}

export interface ConnectionSessionFence {
  id: string;
  teamId: string;
  accessRevision: number;
  steeringRevision: number;
  controlRevision: number;
  runtimeAuthorizationGeneration: number;
}

export interface InboundAttributionResolution {
  readonly direction: "inbound";
  readonly action: "comment" | "directive";
  readonly provider: ConnectionProvider;
  readonly session: Readonly<ConnectionSessionFence>;
  readonly installation: Readonly<{
    id: string;
    revision: number;
    externalTenantId: string;
    externalAppId: string;
    credentialHandleId: string;
    credentialHandleGeneration: number;
  }>;
  readonly binding: Readonly<{
    id: string;
    revision: number;
    conversationKind: ConversationKind;
    externalConversationId: string;
    externalThreadId: string;
    inboundPolicy: Readonly<ChannelInboundPolicy>;
    inboundPolicyDigest: string;
  }>;
  /** Attribution only. This is never Team membership, participation, or steering authority. */
  readonly identity: Readonly<{
    connectionId: string;
    connectionGeneration: number;
    userId: string;
    externalSubject: string;
    scopes: readonly string[];
    scopesDigest: string;
    credentialHandleId: string | null;
    credentialHandleGeneration: number | null;
  }>;
}

export interface OutboundBindingResolution {
  readonly direction: "outbound";
  readonly messageKind: "mention" | "session-message";
  readonly includesArtifacts: boolean;
  readonly provider: ConnectionProvider;
  readonly session: Readonly<ConnectionSessionFence>;
  readonly installation: Readonly<{
    id: string;
    revision: number;
    externalTenantId: string;
    externalAppId: string;
    credentialHandleId: string;
    credentialHandleGeneration: number;
  }>;
  readonly binding: Readonly<{
    id: string;
    revision: number;
    conversationKind: ConversationKind;
    externalConversationId: string;
    externalThreadId: string;
    outboundPolicy: Readonly<ChannelOutboundPolicy>;
    outboundPolicyDigest: string;
  }>;
}

export interface CanonicalStringSet {
  schema: typeof CONNECTION_SET_SCHEMA;
  values: readonly string[];
  json: string;
  digest: string;
}

const SET_VALUE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/;

export function canonicalStringSet(
  input: readonly string[],
  label: string,
  options: { allowEmpty?: boolean; maxItems?: number } = {}
): CanonicalStringSet {
  if (!Array.isArray(input)) throw new TypeError(`${label} must be an array`);
  const maxItems = options.maxItems ?? 128;
  if (!Number.isSafeInteger(maxItems) || maxItems < 1 || input.length > maxItems) {
    throw new TypeError(`${label} is too large`);
  }
  const values = input.map((value) => {
    if (typeof value !== "string" || !SET_VALUE.test(value)) {
      throw new TypeError(`${label} contains an invalid value`);
    }
    return value;
  });
  values.sort();
  for (let index = 1; index < values.length; index += 1) {
    if (values[index] === values[index - 1]) {
      throw new TypeError(`${label} contains a duplicate value`);
    }
  }
  if (!options.allowEmpty && values.length === 0) {
    throw new TypeError(`${label} cannot be empty`);
  }
  const frozen = Object.freeze(values);
  const json = JSON.stringify(frozen);
  if (Buffer.byteLength(json, "utf8") > 16_384) throw new TypeError(`${label} is too large`);
  return Object.freeze({
    schema: CONNECTION_SET_SCHEMA,
    values: frozen,
    json,
    digest: sha256(json),
  });
}

export function canonicalInboundPolicy(input: ChannelInboundPolicy): {
  schema: typeof CHANNEL_BINDING_POLICY_SCHEMA;
  value: Readonly<ChannelInboundPolicy>;
  json: string;
  digest: string;
} {
  if (
    !input ||
    (input.mode !== "comments-only" &&
      input.mode !== "comments-and-directives" &&
      input.mode !== "notifications-only") ||
    typeof input.requireLinkedIdentity !== "boolean"
  ) {
    throw new TypeError("Inbound Channel policy is invalid");
  }
  if (input.mode === "comments-and-directives" && !input.requireLinkedIdentity) {
    throw new TypeError("Inbound directives require a linked identity");
  }
  const value = Object.freeze({
    mode: input.mode,
    requireLinkedIdentity: input.requireLinkedIdentity,
  });
  const json = JSON.stringify(value);
  return Object.freeze({
    schema: CHANNEL_BINDING_POLICY_SCHEMA,
    value,
    json,
    digest: sha256(json),
  });
}

export function canonicalOutboundPolicy(input: ChannelOutboundPolicy): {
  schema: typeof CHANNEL_BINDING_POLICY_SCHEMA;
  value: Readonly<ChannelOutboundPolicy>;
  json: string;
  digest: string;
} {
  if (
    !input ||
    (input.mode !== "disabled" &&
      input.mode !== "mentions" &&
      input.mode !== "all-session-messages") ||
    typeof input.allowArtifacts !== "boolean"
  ) {
    throw new TypeError("Outbound Channel policy is invalid");
  }
  const value = Object.freeze({ mode: input.mode, allowArtifacts: input.allowArtifacts });
  const json = JSON.stringify(value);
  return Object.freeze({
    schema: CHANNEL_BINDING_POLICY_SCHEMA,
    value,
    json,
    digest: sha256(json),
  });
}

export function sha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

export function connectionProvider(value: unknown): ConnectionProvider {
  if (value !== "slack" && value !== "telegram") {
    throw new TypeError("Connection provider is invalid");
  }
  return value;
}

export function credentialBrokerKind(value: unknown): CredentialBrokerKind {
  if (value !== "onepassword-connect" && value !== "oauth-envelope") {
    throw new TypeError("Credential broker kind is invalid");
  }
  return value;
}

export function credentialHandleUsage(value: unknown): CredentialHandleUsage {
  if (value !== "installation" && value !== "identity-connection") {
    throw new TypeError("Credential Handle usage is invalid");
  }
  return value;
}

export function conversationKind(value: unknown): ConversationKind {
  if (value !== "channel" && value !== "thread" && value !== "topic") {
    throw new TypeError("Channel conversation kind is invalid");
  }
  return value;
}

export function boundedIdentifier(value: unknown, label: string, maxLength = 1024): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maxLength ||
    value !== value.trim() ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

export function positiveVersion(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new TypeError(`${label} is invalid`);
  }
  return value as number;
}

export function safeTimestamp(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${label} is invalid`);
  }
  return value as number;
}

export function sha256Digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}
