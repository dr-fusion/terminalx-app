import crypto from "node:crypto";
import type Database from "better-sqlite3";
import {
  CHANNEL_BINDING_POLICY_SCHEMA,
  CONNECTION_SET_SCHEMA,
  LINK_CHALLENGE_MAX_ACTIVE_PER_INSTALLATION,
  LINK_CHALLENGE_MAX_ACTIVE_PER_USER_INSTALLATION,
  LINK_CHALLENGE_MAX_AUTH_AGE_MS,
  LINK_CHALLENGE_MAX_ISSUED_PER_INSTALLATION_WINDOW,
  LINK_CHALLENGE_MAX_ISSUED_PER_USER_INSTALLATION_WINDOW,
  LINK_CHALLENGE_MAX_TTL_MS,
  LINK_CHALLENGE_MIN_TTL_MS,
  LINK_CHALLENGE_ISSUANCE_WINDOW_MS,
  boundedIdentifier,
  canonicalInboundPolicy,
  canonicalOutboundPolicy,
  canonicalStringSet,
  connectionProvider,
  conversationKind,
  credentialBrokerKind,
  credentialHandleUsage,
  positiveVersion,
  safeTimestamp,
  sha256,
  sha256Digest,
  type ChannelBindingView,
  type ChannelInboundPolicy,
  type ChannelInstallationView,
  type ChannelOutboundPolicy,
  type ConnectionActorSnapshot,
  type ConnectionProvider,
  type CredentialBrokerKind,
  type CredentialHandleUsage,
  type IdentityConnectionView,
  type InboundAttributionResolution,
  type IssuedLinkChallenge,
  type OutboundBindingResolution,
} from "./contracts";

export type CredentialHandleAuthorityBinding =
  | Readonly<{
      kind: "installation";
      teamId: string;
      externalTenantId: string;
      externalAppId: string;
    }>
  | Readonly<{
      kind: "identity-connection";
      userId: string;
      installationId: string;
      installationRevision: number;
      externalTenantId: string;
      externalSubject: string;
      providerProofReplayDigest: string;
    }>;

export interface CredentialHandleRegistrationExpectation {
  provider: ConnectionProvider;
  brokerKind: CredentialBrokerKind;
  usage: CredentialHandleUsage;
  authorityBinding: CredentialHandleAuthorityBinding;
  replaces: { handleId: string; generation: number } | null;
}

export interface VerifiedCredentialHandleRegistration extends CredentialHandleRegistrationExpectation {
  handleId: string;
  /** Opaque, single-use broker receipt. TerminalX persists only its digest. */
  receiptId: string;
}

export interface ProviderProofExpectation {
  provider: ConnectionProvider;
  externalTenantId: string;
  externalAppId: string;
  installationId: string;
  installationRevision: number;
  challengeDigest: string;
  requestedScopes: readonly string[];
  requestedScopesDigest: string;
}

export interface VerifiedProviderIdentity {
  provider: ConnectionProvider;
  externalTenantId: string;
  externalAppId: string;
  installationId: string;
  installationRevision: number;
  challengeDigest: string;
  requestedScopesDigest: string;
  externalSubject: string;
  grantedScopes: readonly string[];
  grantedScopesDigest: string;
  /** Opaque provider replay key. TerminalX persists only its digest. */
  proofReplayId: string;
}

export interface StoredAuthenticationSnapshot {
  userId: string;
  username: string;
  userGeneration: number;
  authProvider: "local" | "google" | "password";
  authSubject: string;
  authIdentityId: string;
  authIdentityGeneration: number;
  authenticatedAtMs?: number;
  credentialIssuedAtMs: number;
  credentialExpiresAtMs: number;
  credentialJtiDigest: string;
  device: { provenance: "browser" } | { provenance: "paired-device"; id: string };
}

export interface CreateConnectionAuthorityOptions {
  db: Database.Database;
  clock?: () => number;
  idGenerator?: () => string;
  randomBytes?: (size: number) => Buffer;
  /**
   * Synchronous, local verification of a non-forgeable Secret Broker receipt.
   * The callback must perform no network I/O; broker registration happens
   * before entering this SQLite authority transaction.
   */
  verifyCredentialHandleRegistration?: (input: {
    proof: unknown;
    expected: Readonly<CredentialHandleRegistrationExpectation>;
  }) => VerifiedCredentialHandleRegistration | null;
  /**
   * Injected only by a verified provider adapter. Human HTTP routes never
   * receive an external-subject parameter and cannot complete a challenge by
   * asserting a boolean or constructing an unverified DTO.
   */
  verifyProviderProof?: (input: {
    proof: unknown;
    expected: Readonly<ProviderProofExpectation>;
  }) => VerifiedProviderIdentity | null;
  /** Revalidates auth mode, allowlist, logout JTI, and paired-device status. */
  validateAuthenticationSnapshot?: (snapshot: Readonly<StoredAuthenticationSnapshot>) => boolean;
}

export interface CreateChannelInstallationInput {
  actor: ConnectionActorSnapshot;
  teamId: string;
  provider: ConnectionProvider;
  externalTenantId: string;
  externalAppId: string;
  expectedBrokerKind: CredentialBrokerKind;
  credentialBrokerProof: unknown;
  reviewedScopes: readonly string[];
  capabilities: readonly string[];
  /**
   * Optional caller-generated Channel Installation ID. The Telegram webhook URL
   * must embed the installation id before the broker exchange registers it with
   * the provider, so the installing route pre-generates the id. Validated and
   * uniqueness-enforced exactly like a generated id.
   */
  installationId?: string;
}

export interface IssueLinkChallengeInput {
  actor: ConnectionActorSnapshot;
  installationId: string;
  expectedInstallationRevision: number;
  requestedScopes: readonly string[];
  ttlMs?: number;
}

export interface CompleteLinkChallengeInput {
  challenge: string;
  providerProof: unknown;
  identityCredential?: {
    expectedBrokerKind: CredentialBrokerKind;
    brokerProof: unknown;
  };
}

export interface CreateChannelBindingInput {
  actor: ConnectionActorSnapshot;
  sessionId: string;
  installationId: string;
  expectedInstallationRevision: number;
  conversationKind: "channel" | "thread" | "topic";
  externalConversationId: string;
  externalThreadId?: string;
  inboundPolicy: ChannelInboundPolicy;
  outboundPolicy: ChannelOutboundPolicy;
}

export interface ConnectionAuthority {
  createChannelInstallation(input: CreateChannelInstallationInput): ChannelInstallationView;
  rotateChannelInstallationCredential(input: {
    actor: ConnectionActorSnapshot;
    installationId: string;
    expectedRevision: number;
    expectedHandleGeneration: number;
    brokerProof: unknown;
  }): ChannelInstallationView;
  revokeChannelInstallation(input: {
    actor: ConnectionActorSnapshot;
    installationId: string;
    expectedRevision: number;
  }): ChannelInstallationView;
  issueLinkChallenge(input: IssueLinkChallengeInput): IssuedLinkChallenge;
  completeLinkChallenge(input: CompleteLinkChallengeInput): IdentityConnectionView;
  revokeIdentityConnection(input: {
    actor: ConnectionActorSnapshot;
    connectionId: string;
    expectedGeneration: number;
  }): IdentityConnectionView;
  createChannelBinding(input: CreateChannelBindingInput): ChannelBindingView;
  updateChannelBinding(input: {
    actor: ConnectionActorSnapshot;
    bindingId: string;
    expectedRevision: number;
    expectedInstallationRevision: number;
    inboundPolicy: ChannelInboundPolicy;
    outboundPolicy: ChannelOutboundPolicy;
  }): ChannelBindingView;
  revokeChannelBinding(input: {
    actor: ConnectionActorSnapshot;
    bindingId: string;
    expectedRevision: number;
  }): ChannelBindingView;
  resolveInboundAttribution(input: {
    action: "comment" | "directive";
    provider: ConnectionProvider;
    installationId: string;
    expectedInstallationRevision: number;
    bindingId: string;
    expectedBindingRevision: number;
    externalTenantId: string;
    externalSubject: string;
    conversationKind: "channel" | "thread" | "topic";
    externalConversationId: string;
    externalThreadId?: string;
  }): InboundAttributionResolution | null;
  resolveOutboundBinding(input: {
    bindingId: string;
    expectedBindingRevision: number;
    expectedInstallationRevision: number;
    messageKind: "mention" | "session-message";
    includesArtifacts: boolean;
  }): OutboundBindingResolution | null;
}

interface ResolvedActor {
  userId: string;
  username: string;
  userGeneration: number;
  authProvider: "local" | "google" | "password";
  authSubject: string;
  authIdentityId: string;
  authIdentityGeneration: number;
  authenticatedAtMs?: number;
  credentialIssuedAtMs: number;
  credentialExpiresAtMs: number;
  credentialJtiDigest: string;
  device: { provenance: "browser" } | { provenance: "paired-device"; id: string };
}

interface ActorRow {
  user_id: string;
  username: string;
  user_generation: number;
  auth_provider: "local" | "google" | "password";
  auth_subject: string;
  auth_identity_id: string;
  auth_identity_generation: number;
}

interface MembershipRow {
  role: "owner" | "admin" | "member" | "guest";
  version: number;
}

interface HandleRow {
  id: string;
  provider: ConnectionProvider;
  broker_kind: CredentialBrokerKind;
  usage: CredentialHandleUsage;
  broker_receipt_digest: string;
  authority_binding_digest: string;
  team_id: string | null;
  user_id: string | null;
  external_tenant_id: string;
  external_app_id: string | null;
  identity_installation_id: string | null;
  identity_installation_revision: number | null;
  external_subject: string | null;
  provider_proof_replay_digest: string | null;
  status: "active" | "revoked";
  generation: number;
  replaces_handle_id: string | null;
  replaces_generation: number | null;
  created_at_ms: number;
  updated_at_ms: number;
  revoked_at_ms: number | null;
}

interface InstallationRow {
  id: string;
  team_id: string;
  provider: ConnectionProvider;
  external_tenant_id: string;
  external_app_id: string;
  credential_handle_id: string;
  credential_handle_generation: number;
  reviewed_scopes_schema: number;
  reviewed_scopes_json: string;
  reviewed_scopes_digest: string;
  capabilities_schema: number;
  capabilities_json: string;
  capabilities_digest: string;
  status: "active" | "revoked";
  revision: number;
  created_at_ms: number;
  updated_at_ms: number;
  revoked_at_ms: number | null;
}

interface ChallengeRow {
  id: string;
  user_id: string;
  user_generation: number;
  auth_identity_id: string;
  auth_identity_generation: number;
  auth_session_issued_at_ms: number;
  auth_session_expires_at_ms: number;
  auth_session_jti_digest: string;
  auth_session_provenance: "browser" | "paired-device";
  auth_session_device_id: string | null;
  team_id: string;
  team_membership_version: number;
  installation_id: string;
  installation_revision: number;
  requested_scopes_schema: number;
  requested_scopes_json: string;
  requested_scopes_digest: string;
  status: "active" | "consumed" | "revoked";
  version: number;
  authenticated_at_ms: number;
  issued_at_ms: number;
  expires_at_ms: number;
  provider_proof_replay_digest: string | null;
}

interface SessionRow {
  id: string;
  team_id: string;
  status: "active" | "awaiting_assignee" | "ended";
  access_revision: number;
  steering_revision: number;
  control_revision: number;
  runtime_authorization_generation: number;
}

interface ConnectionRow {
  id: string;
  user_id: string;
  provider: ConnectionProvider;
  external_tenant_id: string;
  external_subject: string;
  installation_id: string;
  installation_revision: number;
  scopes_schema: number;
  scopes_json: string;
  scopes_digest: string;
  credential_handle_id: string | null;
  credential_handle_generation: number | null;
  provider_proof_replay_digest: string;
  status: "active" | "revoked";
  generation: number;
  created_at_ms: number;
  updated_at_ms: number;
  revoked_at_ms: number | null;
}

interface BindingRow {
  id: string;
  session_id: string;
  team_id: string;
  installation_id: string;
  installation_revision: number;
  provider: ConnectionProvider;
  conversation_kind: "channel" | "thread" | "topic";
  external_conversation_id: string;
  external_thread_id: string;
  policy_schema: number;
  inbound_policy_json: string;
  inbound_policy_digest: string;
  outbound_policy_json: string;
  outbound_policy_digest: string;
  status: "active" | "revoked";
  revision: number;
  created_at_ms: number;
  updated_at_ms: number;
  revoked_at_ms: number | null;
}

const HANDLE_COLUMNS = `
  id, provider, broker_kind, usage, broker_receipt_digest, authority_binding_digest,
  team_id, user_id, external_tenant_id, external_app_id,
  identity_installation_id, identity_installation_revision, external_subject,
  provider_proof_replay_digest, status, generation,
  replaces_handle_id, replaces_generation, created_at_ms, updated_at_ms, revoked_at_ms
`;
const INSTALLATION_COLUMNS = `
  id, team_id, provider, external_tenant_id, external_app_id,
  credential_handle_id, credential_handle_generation,
  reviewed_scopes_schema, reviewed_scopes_json, reviewed_scopes_digest,
  capabilities_schema, capabilities_json, capabilities_digest,
  status, revision, created_at_ms, updated_at_ms, revoked_at_ms
`;
const CONNECTION_COLUMNS = `
  id, user_id, provider, external_tenant_id, external_subject,
  installation_id, installation_revision, scopes_schema, scopes_json, scopes_digest,
  credential_handle_id, credential_handle_generation, provider_proof_replay_digest,
  status, generation, created_at_ms, updated_at_ms, revoked_at_ms
`;
const BINDING_COLUMNS = `
  id, session_id, team_id, installation_id, installation_revision,
  provider, conversation_kind, external_conversation_id, external_thread_id,
  policy_schema, inbound_policy_json, inbound_policy_digest,
  outbound_policy_json, outbound_policy_digest,
  status, revision, created_at_ms, updated_at_ms, revoked_at_ms
`;

export function createConnectionAuthority(
  options: CreateConnectionAuthorityOptions
): ConnectionAuthority {
  const clock = options.clock ?? Date.now;
  const idGenerator = options.idGenerator ?? crypto.randomUUID;
  const randomBytes = options.randomBytes ?? crypto.randomBytes;

  const findActor = options.db.prepare(
    `SELECT user.id AS user_id, user.username,
            user.generation AS user_generation,
            identity.id AS auth_identity_id,
            identity.provider AS auth_provider, identity.subject AS auth_subject,
            identity.generation AS auth_identity_generation
     FROM users user
     JOIN auth_identities identity ON identity.user_id = user.id
     WHERE user.id = ? AND user.generation = ? AND user.status = 'active'
       AND identity.provider = ? AND identity.subject = ?
       AND identity.generation = ? AND identity.status = 'active'`
  );
  const findMembership = options.db.prepare(
    `SELECT role, version FROM team_memberships
     WHERE team_id = ? AND user_id = ? AND status = 'active'`
  );
  const findHandle = options.db.prepare(
    `SELECT ${HANDLE_COLUMNS} FROM credential_handles WHERE id = ?`
  );
  const findInstallation = options.db.prepare(
    `SELECT ${INSTALLATION_COLUMNS} FROM channel_installations WHERE id = ?`
  );
  const findChallengeByDigest = options.db.prepare(
    `SELECT id, user_id, user_generation, auth_identity_id, auth_identity_generation,
            auth_session_issued_at_ms, auth_session_jti_digest,
            auth_session_expires_at_ms,
            auth_session_provenance, auth_session_device_id,
            team_id, team_membership_version, installation_id, installation_revision,
            requested_scopes_schema, requested_scopes_json, requested_scopes_digest,
            authenticated_at_ms, status, version, issued_at_ms, expires_at_ms,
            provider_proof_replay_digest
     FROM link_challenges WHERE challenge_digest = ?`
  );
  const findConnection = options.db.prepare(
    `SELECT ${CONNECTION_COLUMNS} FROM identity_connections WHERE id = ?`
  );
  const findActiveConnectionByExternalIdentity = options.db.prepare(
    `SELECT ${CONNECTION_COLUMNS} FROM identity_connections
     WHERE installation_id = ? AND provider = ? AND external_tenant_id = ?
       AND external_subject = ? AND status = 'active'`
  );
  const findActiveUser = options.db.prepare(
    `SELECT id FROM users WHERE id = ? AND status = 'active'`
  );
  const findBinding = options.db.prepare(
    `SELECT ${BINDING_COLUMNS} FROM channel_bindings WHERE id = ?`
  );
  const findSession = options.db.prepare(
    `SELECT id, team_id, status, access_revision, steering_revision,
            control_revision, runtime_authorization_generation
     FROM sessions WHERE id = ?`
  );
  const countActiveChallengesForUserInstallation = options.db.prepare(
    `SELECT COUNT(*) AS count FROM link_challenges
     WHERE user_id = ? AND installation_id = ? AND status = 'active' AND expires_at_ms >= ?`
  );
  const countActiveChallengesForInstallation = options.db.prepare(
    `SELECT COUNT(*) AS count FROM link_challenges
     WHERE installation_id = ? AND status = 'active' AND expires_at_ms >= ?`
  );
  const countIssuedChallengesForUserInstallationWindow = options.db.prepare(
    `SELECT COUNT(*) AS count FROM link_challenges
     WHERE user_id = ? AND installation_id = ? AND issued_at_ms >= ?`
  );
  const countIssuedChallengesForInstallationWindow = options.db.prepare(
    `SELECT COUNT(*) AS count FROM link_challenges
     WHERE installation_id = ? AND issued_at_ms >= ?`
  );
  const insertLedger = options.db.prepare(
    `INSERT INTO connection_authority_ledger (
       event_id, event_type, actor_kind, actor_user_id, actor_user_generation,
       actor_auth_identity_id, actor_auth_identity_generation,
       resource_kind, resource_id, resource_version,
       team_id, session_id, subject_user_id, provider, detail_digest, occurred_at_ms
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  function resolveActor(input: ConnectionActorSnapshot): ResolvedActor {
    const userId = boundedIdentifier(input.userId, "Connection actor User ID", 300);
    const userGeneration = positiveVersion(
      input.userGeneration,
      "Connection actor User generation"
    );
    const authProvider = authenticationProvider(input.authProvider);
    const authSubject = boundedIdentifier(
      input.authSubject,
      "Connection actor authentication subject"
    );
    const authIdentityGeneration = positiveVersion(
      input.authIdentityGeneration,
      "Connection actor authentication identity generation"
    );
    const credentialIssuedAtMs = safeTimestamp(
      input.credentialIssuedAtMs,
      "Connection actor credential issue time"
    );
    const credentialExpiresAtMs = safeTimestamp(
      input.credentialExpiresAtMs,
      "Connection actor credential expiry time"
    );
    if (
      credentialExpiresAtMs <= credentialIssuedAtMs ||
      credentialExpiresAtMs <= currentTime(clock)
    ) {
      throw new Error("Connection actor credential is expired");
    }
    const credentialJtiDigest = sha256Digest(
      input.credentialJtiDigest,
      "Connection actor credential ID digest"
    );
    const authenticatedAtMs =
      input.authenticatedAtMs === undefined
        ? undefined
        : safeTimestamp(input.authenticatedAtMs, "Connection actor authentication time");
    let device: ResolvedActor["device"];
    if (input.device?.provenance === "browser") {
      device = Object.freeze({ provenance: "browser" });
    } else if (input.device?.provenance === "paired-device") {
      device = Object.freeze({
        provenance: "paired-device",
        id: boundedIdentifier(input.device.id, "Connection actor device ID", 300),
      });
    } else {
      throw new TypeError("Connection actor device provenance is invalid");
    }
    const row = findActor.get(
      userId,
      userGeneration,
      authProvider,
      authSubject,
      authIdentityGeneration
    ) as ActorRow | undefined;
    if (!row) throw new Error("Connection actor snapshot is stale");
    const actor = Object.freeze({
      userId: row.user_id,
      username: row.username,
      userGeneration: row.user_generation,
      authProvider: row.auth_provider,
      authSubject: row.auth_subject,
      authIdentityId: row.auth_identity_id,
      authIdentityGeneration: row.auth_identity_generation,
      ...(authenticatedAtMs === undefined ? {} : { authenticatedAtMs }),
      credentialIssuedAtMs,
      credentialExpiresAtMs,
      credentialJtiDigest,
      device,
    });
    if (!authenticationSnapshotIsActive(actor)) {
      throw new Error("Connection authentication session is unavailable");
    }
    return actor;
  }

  function membership(teamIdInput: string, actor: ResolvedActor): MembershipRow {
    const teamId = boundedIdentifier(teamIdInput, "Team ID", 300);
    const row = findMembership.get(teamId, actor.userId) as MembershipRow | undefined;
    if (!row) throw new Error("Active Team membership is required");
    return row;
  }

  function adminMembership(teamId: string, actor: ResolvedActor): MembershipRow {
    const row = membership(teamId, actor);
    if (row.role !== "owner" && row.role !== "admin") {
      throw new Error("Team owner or admin authority is required");
    }
    return row;
  }

  function authenticationSnapshotIsActive(actor: ResolvedActor): boolean {
    try {
      return options.validateAuthenticationSnapshot?.(authenticationSnapshot(actor)) === true;
    } catch {
      return false;
    }
  }

  function requireActiveAuthenticationBoundary(actor: ResolvedActor): number {
    const now = currentTime(clock);
    if (actor.credentialExpiresAtMs <= now || !authenticationSnapshotIsActive(actor)) {
      throw new Error("Connection authentication session is unavailable");
    }
    return now;
  }

  function appendLedger(input: {
    eventType: string;
    actorKind: "human" | "provider" | "system";
    actor?: ResolvedActor;
    resourceKind:
      | "credential-handle"
      | "channel-installation"
      | "link-challenge"
      | "identity-connection"
      | "channel-binding";
    resourceId: string;
    resourceVersion: number;
    teamId?: string;
    sessionId?: string;
    subjectUserId?: string;
    provider?: ConnectionProvider;
    detail: Readonly<Record<string, string | number | boolean | null>>;
    occurredAtMs: number;
  }): void {
    const actor = input.actor;
    insertLedger.run(
      generatedId(idGenerator, "connection authority event ID"),
      input.eventType,
      input.actorKind,
      actor?.userId ?? null,
      actor?.userGeneration ?? null,
      actor?.authIdentityId ?? null,
      actor?.authIdentityGeneration ?? null,
      input.resourceKind,
      input.resourceId,
      input.resourceVersion,
      input.teamId ?? null,
      input.sessionId ?? null,
      input.subjectUserId ?? null,
      input.provider ?? null,
      sha256(JSON.stringify(input.detail)),
      input.occurredAtMs
    );
  }

  function revokeActiveChallengesForInstallation(input: {
    installation: InstallationRow;
    actor: ResolvedActor;
    now: number;
    reason: "installationRotated" | "installationRevoked";
  }): void {
    const challenges = options.db
      .prepare(
        `SELECT id, version, user_id, requested_scopes_digest
         FROM link_challenges
         WHERE installation_id = ? AND status = 'active' AND expires_at_ms >= ?
         ORDER BY id`
      )
      .all(input.installation.id, input.now) as Array<{
      id: string;
      version: number;
      user_id: string;
      requested_scopes_digest: string;
    }>;
    if (challenges.length > LINK_CHALLENGE_MAX_ACTIVE_PER_INSTALLATION) {
      throw new Error("Active Link Challenge limit integrity check failed");
    }
    for (const challenge of challenges) {
      const challengeRevoked = options.db
        .prepare(
          `UPDATE link_challenges
           SET status = 'revoked', version = version + 1, resolved_at_ms = ?
           WHERE id = ? AND status = 'active' AND version = ?`
        )
        .run(input.now, challenge.id, challenge.version);
      if (challengeRevoked.changes !== 1) {
        throw new Error("Link Challenge revocation was fenced");
      }
      appendLedger({
        eventType: "link-challenge.revoked",
        actorKind: "human",
        actor: input.actor,
        resourceKind: "link-challenge",
        resourceId: challenge.id,
        resourceVersion: challenge.version + 1,
        teamId: input.installation.team_id,
        subjectUserId: challenge.user_id,
        provider: input.installation.provider,
        detail: {
          [input.reason]: true,
          requestedScopesDigest: challenge.requested_scopes_digest,
        },
        occurredAtMs: input.now,
      });
    }
  }

  function registerVerifiedCredentialHandle(input: {
    actor: ResolvedActor;
    actorKind: "human" | "provider";
    provider: ConnectionProvider;
    brokerKind: CredentialBrokerKind;
    authorityBinding: CredentialHandleAuthorityBinding;
    replaces: { handleId: string; generation: number } | null;
    brokerProof: unknown;
    now: number;
    /** Runs after local proof verification and immediately before persistence. */
    beforePersist?: () => number;
  }): HandleRow {
    if (!options.verifyCredentialHandleRegistration) {
      throw new Error("Verified Secret Broker registration is unavailable");
    }
    const usage = input.authorityBinding.kind;
    const expected = Object.freeze({
      provider: input.provider,
      brokerKind: input.brokerKind,
      usage,
      authorityBinding: input.authorityBinding,
      replaces: input.replaces,
    });
    let handleId: string;
    let receiptId: string;
    try {
      const registration = options.verifyCredentialHandleRegistration({
        proof: input.brokerProof,
        expected,
      });
      if (!registration || !sameHandleRegistrationExpectation(registration, expected)) {
        throw new Error("misbound Secret Broker registration");
      }
      handleId = credentialHandleId(registration.handleId);
      if (input.replaces?.handleId === handleId) {
        throw new Error("Secret Broker rotation reused the handle");
      }
      receiptId = boundedIdentifier(
        registration.receiptId,
        "Secret Broker registration receipt",
        2048
      );
    } catch {
      throw new Error("Verified Secret Broker registration is invalid or misbound");
    }
    const receiptDigest = credentialBrokerReceiptDigest({
      provider: input.provider,
      brokerKind: input.brokerKind,
      receiptId,
    });
    const bindingDigest = credentialHandleAuthorityBindingDigest(
      input.provider,
      input.authorityBinding
    );
    const columns = handleAuthorityColumns(input.authorityBinding);
    const persistedAtMs = input.beforePersist?.() ?? input.now;
    options.db
      .prepare(
        `INSERT INTO credential_handles (
           id, provider, broker_kind, usage, broker_receipt_digest,
           authority_binding_digest, team_id, user_id, external_tenant_id,
           external_app_id, identity_installation_id, identity_installation_revision,
           external_subject, provider_proof_replay_digest,
           status, generation, replaces_handle_id, replaces_generation,
           created_by_user_id, created_by_user_generation,
           created_by_auth_identity_id, created_by_auth_identity_generation,
           updated_by_user_id, updated_by_user_generation,
           updated_by_auth_identity_id, updated_by_auth_identity_generation,
           created_at_ms, updated_at_ms, revoked_at_ms
         ) VALUES (
           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 1, ?, ?,
           ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL
         )`
      )
      .run(
        handleId,
        input.provider,
        input.brokerKind,
        usage,
        receiptDigest,
        bindingDigest,
        columns.teamId,
        columns.userId,
        columns.externalTenantId,
        columns.externalAppId,
        columns.identityInstallationId,
        columns.identityInstallationRevision,
        columns.externalSubject,
        columns.providerProofReplayDigest,
        input.replaces?.handleId ?? null,
        input.replaces?.generation ?? null,
        input.actor.userId,
        input.actor.userGeneration,
        input.actor.authIdentityId,
        input.actor.authIdentityGeneration,
        input.actor.userId,
        input.actor.userGeneration,
        input.actor.authIdentityId,
        input.actor.authIdentityGeneration,
        persistedAtMs,
        persistedAtMs
      );
    appendLedger({
      eventType: "credential-handle.registered",
      actorKind: input.actorKind,
      actor: input.actor,
      resourceKind: "credential-handle",
      resourceId: handleId,
      resourceVersion: 1,
      ...(columns.teamId === null ? {} : { teamId: columns.teamId }),
      ...(columns.userId === null ? {} : { subjectUserId: columns.userId }),
      provider: input.provider,
      detail: {
        brokerKind: input.brokerKind,
        usage,
        status: "active",
        receiptDigest,
        bindingDigest,
      },
      occurredAtMs: persistedAtMs,
    });
    return requireRow(findHandle.get(handleId) as HandleRow | undefined, "Credential Handle");
  }

  const createChannelInstallation = options.db.transaction(
    (input: CreateChannelInstallationInput): ChannelInstallationView => {
      const actor = resolveActor(input.actor);
      const teamId = boundedIdentifier(input.teamId, "Team ID", 300);
      const member = adminMembership(teamId, actor);
      const provider = connectionProvider(input.provider);
      const externalTenantId = boundedIdentifier(input.externalTenantId, "external tenant ID");
      const externalAppId = boundedIdentifier(input.externalAppId, "external application ID");
      const brokerKind = credentialBrokerKind(input.expectedBrokerKind);
      const scopes = canonicalStringSet(input.reviewedScopes, "reviewed provider scopes");
      const capabilities = canonicalStringSet(input.capabilities, "reviewed provider capabilities");
      const now = currentTime(clock);
      const installationId =
        input.installationId === undefined
          ? generatedId(idGenerator, "Channel Installation ID")
          : boundedIdentifier(input.installationId, "Channel Installation ID", 300);
      const handle = registerVerifiedCredentialHandle({
        actor,
        actorKind: "human",
        provider,
        brokerKind,
        authorityBinding: Object.freeze({
          kind: "installation",
          teamId,
          externalTenantId,
          externalAppId,
        }),
        replaces: null,
        brokerProof: input.credentialBrokerProof,
        now,
        beforePersist: () => requireActiveAuthenticationBoundary(actor),
      });
      options.db
        .prepare(
          `INSERT INTO channel_installations (
             id, team_id, provider, external_tenant_id, external_app_id,
             credential_handle_id, credential_handle_generation,
             reviewed_scopes_schema, reviewed_scopes_json, reviewed_scopes_digest,
             capabilities_schema, capabilities_json, capabilities_digest,
             status, revision,
             created_by_user_id, created_under_membership_version,
             created_by_user_generation, created_by_auth_identity_id,
             created_by_auth_identity_generation,
             updated_by_user_id, updated_under_membership_version,
             updated_by_user_generation, updated_by_auth_identity_id,
             updated_by_auth_identity_generation,
             created_at_ms, updated_at_ms, revoked_at_ms
           ) VALUES (
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 1,
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL
           )`
        )
        .run(
          installationId,
          teamId,
          provider,
          externalTenantId,
          externalAppId,
          handle.id,
          handle.generation,
          scopes.schema,
          scopes.json,
          scopes.digest,
          capabilities.schema,
          capabilities.json,
          capabilities.digest,
          actor.userId,
          member.version,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          actor.userId,
          member.version,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          handle.created_at_ms,
          handle.created_at_ms
        );
      appendLedger({
        eventType: "channel-installation.created",
        actorKind: "human",
        actor,
        resourceKind: "channel-installation",
        resourceId: installationId,
        resourceVersion: 1,
        teamId,
        provider,
        detail: {
          status: "active",
          reviewedScopesDigest: scopes.digest,
          capabilitiesDigest: capabilities.digest,
          credentialHandleGeneration: handle.generation,
        },
        occurredAtMs: handle.created_at_ms,
      });
      return installationView(
        requireRow(
          findInstallation.get(installationId) as InstallationRow | undefined,
          "Channel Installation"
        )
      );
    }
  );

  const rotateChannelInstallationCredential = options.db.transaction(
    (input: {
      actor: ConnectionActorSnapshot;
      installationId: string;
      expectedRevision: number;
      expectedHandleGeneration: number;
      brokerProof: unknown;
    }): ChannelInstallationView => {
      const actor = resolveActor(input.actor);
      const installationId = boundedIdentifier(
        input.installationId,
        "Channel Installation ID",
        300
      );
      const expectedRevision = positiveVersion(
        input.expectedRevision,
        "Channel Installation revision"
      );
      const expectedHandleGeneration = positiveVersion(
        input.expectedHandleGeneration,
        "Credential Handle generation"
      );
      const installation = requireActiveInstallation(findInstallation, installationId);
      if (
        installation.revision !== expectedRevision ||
        installation.credential_handle_generation !== expectedHandleGeneration
      ) {
        throw new Error("Channel Installation credential rotation was fenced");
      }
      const member = adminMembership(installation.team_id, actor);
      const oldHandle = requireActiveHandle(
        findHandle,
        installation.credential_handle_id,
        expectedHandleGeneration,
        installation.provider,
        "installation"
      );
      const authorityBinding = installationHandleAuthorityBinding(installation);
      requireHandleAuthorityBinding(oldHandle, installation.provider, authorityBinding);
      const now = currentTime(clock);
      revokeHandleRow(options.db, oldHandle, actor, now);
      appendLedger({
        eventType: "credential-handle.revoked",
        actorKind: "human",
        actor,
        resourceKind: "credential-handle",
        resourceId: oldHandle.id,
        resourceVersion: oldHandle.generation + 1,
        teamId: installation.team_id,
        provider: oldHandle.provider,
        detail: { status: "revoked", replacement: true },
        occurredAtMs: now,
      });
      const replacement = registerVerifiedCredentialHandle({
        actor,
        actorKind: "human",
        provider: oldHandle.provider,
        brokerKind: oldHandle.broker_kind,
        authorityBinding,
        replaces: Object.freeze({ handleId: oldHandle.id, generation: oldHandle.generation + 1 }),
        brokerProof: input.brokerProof,
        now,
        beforePersist: () => requireActiveAuthenticationBoundary(actor),
      });
      const completedAtMs = replacement.created_at_ms;
      const updated = options.db
        .prepare(
          `UPDATE channel_installations
           SET credential_handle_id = ?, credential_handle_generation = 1,
               revision = revision + 1,
               updated_by_user_id = ?, updated_under_membership_version = ?,
               updated_by_user_generation = ?, updated_by_auth_identity_id = ?,
               updated_by_auth_identity_generation = ?, updated_at_ms = ?
           WHERE id = ? AND status = 'active' AND revision = ?`
        )
        .run(
          replacement.id,
          actor.userId,
          member.version,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          completedAtMs,
          installationId,
          expectedRevision
        );
      if (updated.changes !== 1) throw new Error("Channel Installation rotation was fenced");
      revokeActiveChallengesForInstallation({
        installation,
        actor,
        now: completedAtMs,
        reason: "installationRotated",
      });
      appendLedger({
        eventType: "channel-installation.updated",
        actorKind: "human",
        actor,
        resourceKind: "channel-installation",
        resourceId: installationId,
        resourceVersion: expectedRevision + 1,
        teamId: installation.team_id,
        provider: installation.provider,
        detail: { credentialRotated: true, credentialHandleGeneration: 1 },
        occurredAtMs: completedAtMs,
      });
      return installationView(
        requireRow(
          findInstallation.get(installationId) as InstallationRow | undefined,
          "Channel Installation"
        )
      );
    }
  );

  const issueLinkChallenge = options.db.transaction(
    (input: IssueLinkChallengeInput): IssuedLinkChallenge => {
      const actor = resolveActor(input.actor);
      const now = currentTime(clock);
      if (
        actor.authenticatedAtMs === undefined ||
        actor.authenticatedAtMs > now ||
        now - actor.authenticatedAtMs > LINK_CHALLENGE_MAX_AUTH_AGE_MS ||
        actor.credentialIssuedAtMs > now
      ) {
        throw new Error("Recent primary authentication is required");
      }
      if (!authenticationSnapshotIsActive(actor)) {
        throw new Error("Connection authentication session is unavailable");
      }
      const installationId = boundedIdentifier(
        input.installationId,
        "Channel Installation ID",
        300
      );
      const expectedRevision = positiveVersion(
        input.expectedInstallationRevision,
        "Channel Installation revision"
      );
      const installation = requireActiveInstallation(findInstallation, installationId);
      if (installation.revision !== expectedRevision) {
        throw new Error("Channel Installation revision is stale");
      }
      requireActiveInstallationCredentialHandle(findHandle, installation);
      const member = membership(installation.team_id, actor);
      const issuanceWindowStart = Math.max(0, now - LINK_CHALLENGE_ISSUANCE_WINDOW_MS);
      const issuedForUser = countIssuedChallengesForUserInstallationWindow.get(
        actor.userId,
        installation.id,
        issuanceWindowStart
      ) as { count: number };
      if (issuedForUser.count >= LINK_CHALLENGE_MAX_ISSUED_PER_USER_INSTALLATION_WINDOW) {
        throw new Error("Link Challenge issuance rate exceeded for this User and Installation");
      }
      const issuedForInstallation = countIssuedChallengesForInstallationWindow.get(
        installation.id,
        issuanceWindowStart
      ) as { count: number };
      if (issuedForInstallation.count >= LINK_CHALLENGE_MAX_ISSUED_PER_INSTALLATION_WINDOW) {
        throw new Error("Link Challenge issuance rate exceeded for this Installation");
      }
      const activeForUser = countActiveChallengesForUserInstallation.get(
        actor.userId,
        installation.id,
        now
      ) as { count: number };
      if (activeForUser.count >= LINK_CHALLENGE_MAX_ACTIVE_PER_USER_INSTALLATION) {
        throw new Error("Too many active Link Challenges for this User and Installation");
      }
      const activeForInstallation = countActiveChallengesForInstallation.get(
        installation.id,
        now
      ) as { count: number };
      if (activeForInstallation.count >= LINK_CHALLENGE_MAX_ACTIVE_PER_INSTALLATION) {
        throw new Error("Too many active Link Challenges for this Installation");
      }
      const reviewedScopes = storedStringSet(
        installation.reviewed_scopes_schema,
        installation.reviewed_scopes_json,
        installation.reviewed_scopes_digest,
        "Channel Installation reviewed scopes"
      );
      const requestedScopes = canonicalStringSet(
        input.requestedScopes,
        "requested provider scopes"
      );
      const reviewed = new Set(reviewedScopes.values);
      if (requestedScopes.values.some((scope) => !reviewed.has(scope))) {
        throw new Error("Requested provider scope was not reviewed");
      }
      const ttlMs =
        input.ttlMs === undefined
          ? LINK_CHALLENGE_MAX_TTL_MS
          : safeTimestamp(input.ttlMs, "Link Challenge TTL");
      if (ttlMs < LINK_CHALLENGE_MIN_TTL_MS || ttlMs > LINK_CHALLENGE_MAX_TTL_MS) {
        throw new TypeError("Link Challenge TTL is invalid");
      }
      const requestedExpiresAtMs = now + ttlMs;
      if (!Number.isSafeInteger(requestedExpiresAtMs))
        throw new TypeError("Link Challenge expiry is invalid");
      const expiresAtMs = Math.min(requestedExpiresAtMs, actor.credentialExpiresAtMs);
      if (expiresAtMs < now + LINK_CHALLENGE_MIN_TTL_MS) {
        throw new Error("Source credential expires too soon for a Link Challenge");
      }
      const challenge = generatedChallenge(randomBytes);
      const challengeId = generatedId(idGenerator, "Link Challenge ID");
      options.db
        .prepare(
          `INSERT INTO link_challenges (
             id, challenge_digest, user_id, user_generation,
             auth_identity_id, auth_identity_generation, auth_session_jti_digest,
             auth_session_issued_at_ms, auth_session_expires_at_ms,
             auth_session_provenance, auth_session_device_id,
             team_id, team_membership_version, installation_id, installation_revision,
             requested_scopes_schema, requested_scopes_json, requested_scopes_digest,
             authenticated_at_ms, status, version, issued_at_ms, expires_at_ms,
             resolved_at_ms, provider_proof_replay_digest
           ) VALUES (
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             'active', 1, ?, ?, NULL, NULL
           )`
        )
        .run(
          challengeId,
          sha256(challenge),
          actor.userId,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          actor.credentialJtiDigest,
          actor.credentialIssuedAtMs,
          actor.credentialExpiresAtMs,
          actor.device.provenance,
          actor.device.provenance === "paired-device" ? actor.device.id : null,
          installation.team_id,
          member.version,
          installation.id,
          installation.revision,
          requestedScopes.schema,
          requestedScopes.json,
          requestedScopes.digest,
          actor.authenticatedAtMs,
          now,
          expiresAtMs
        );
      appendLedger({
        eventType: "link-challenge.issued",
        actorKind: "human",
        actor,
        resourceKind: "link-challenge",
        resourceId: challengeId,
        resourceVersion: 1,
        teamId: installation.team_id,
        subjectUserId: actor.userId,
        provider: installation.provider,
        detail: {
          requestedScopesDigest: requestedScopes.digest,
          installationRevision: installation.revision,
          expiresAtMs,
        },
        occurredAtMs: now,
      });
      return Object.freeze({
        challenge,
        expiresAtMs,
        installationId: installation.id,
        installationRevision: installation.revision,
        requestedScopes: requestedScopes.values,
      });
    }
  );

  const completeLinkChallenge = options.db.transaction(
    (input: CompleteLinkChallengeInput): IdentityConnectionView => {
      if (!options.verifyProviderProof) {
        throw new Error("Verified provider completion is unavailable");
      }
      if (!options.validateAuthenticationSnapshot) {
        throw new Error("Connection authentication validation is unavailable");
      }
      const challengeValue = boundedIdentifier(input.challenge, "Link Challenge", 256);
      if (!/^txlc_v1_[0-9a-f]{64}$/.test(challengeValue)) {
        throw new TypeError("Link Challenge is invalid");
      }
      const challengeDigest = sha256(challengeValue);
      const challenge = findChallengeByDigest.get(challengeDigest) as ChallengeRow | undefined;
      if (
        !challenge ||
        challenge.status !== "active" ||
        challenge.provider_proof_replay_digest !== null
      ) {
        throw new Error("Link Challenge is invalid or already used");
      }
      const initiallyCheckedAtMs = currentTime(clock);
      if (
        initiallyCheckedAtMs >= challenge.expires_at_ms ||
        initiallyCheckedAtMs >= challenge.auth_session_expires_at_ms
      ) {
        throw new Error("Link Challenge expired");
      }
      const actor = requireStoredActor(options.db, challenge);
      if (!authenticationSnapshotIsActive(actor)) {
        throw new Error("Link Challenge authentication session changed");
      }
      const member = membership(challenge.team_id, actor);
      if (member.version !== challenge.team_membership_version) {
        throw new Error("Link Challenge Team membership changed");
      }
      const installation = requireActiveInstallation(findInstallation, challenge.installation_id);
      if (
        installation.team_id !== challenge.team_id ||
        installation.revision !== challenge.installation_revision
      ) {
        throw new Error("Link Challenge installation changed");
      }
      requireActiveInstallationCredentialHandle(findHandle, installation);
      const requestedScopes = storedStringSet(
        challenge.requested_scopes_schema,
        challenge.requested_scopes_json,
        challenge.requested_scopes_digest,
        "Link Challenge scopes"
      );
      const proofExpectation = Object.freeze({
        provider: installation.provider,
        externalTenantId: installation.external_tenant_id,
        externalAppId: installation.external_app_id,
        installationId: installation.id,
        installationRevision: installation.revision,
        challengeDigest,
        requestedScopes: requestedScopes.values,
        requestedScopesDigest: requestedScopes.digest,
      });
      let provider: ConnectionProvider;
      let externalTenantId: string;
      let externalSubject: string;
      let proofReplayDigest: string;
      let grantedScopes: ReturnType<typeof canonicalStringSet>;
      try {
        const proof = options.verifyProviderProof({
          proof: input.providerProof,
          expected: proofExpectation,
        });
        if (!proof || !sameProviderProofExpectation(proof, proofExpectation)) {
          throw new Error("misbound provider proof");
        }
        provider = connectionProvider(proof.provider);
        externalTenantId = boundedIdentifier(proof.externalTenantId, "external tenant ID");
        externalSubject = boundedIdentifier(proof.externalSubject, "external provider subject");
        const proofReplayId = boundedIdentifier(
          proof.proofReplayId,
          "provider proof replay ID",
          2048
        );
        proofReplayDigest = providerProofReplayDigest({
          provider,
          externalTenantId,
          externalAppId: installation.external_app_id,
          proofReplayId,
        });
        grantedScopes = canonicalStringSet(proof.grantedScopes, "verified provider granted scopes");
        if (
          sha256Digest(proof.grantedScopesDigest, "verified provider granted scopes digest") !==
            grantedScopes.digest ||
          grantedScopes.digest !== requestedScopes.digest ||
          grantedScopes.json !== requestedScopes.json
        ) {
          throw new Error("misbound provider scopes");
        }
      } catch {
        throw new Error("Verified provider proof is invalid or misbound");
      }
      let identityHandleId: string | null = null;
      let identityHandleGeneration: number | null = null;
      const identityBrokerKind = input.identityCredential
        ? credentialBrokerKind(input.identityCredential.expectedBrokerKind)
        : null;
      const conflictingOwner = options.db
        .prepare(
          `SELECT user_id
           FROM identity_connections
           WHERE provider = ? AND external_tenant_id = ? AND external_subject = ?
             AND user_id <> ?
           LIMIT 1`
        )
        .get(provider, externalTenantId, externalSubject, challenge.user_id) as
        | { user_id: string }
        | undefined;
      if (conflictingOwner) {
        throw new Error("External identity attribution cannot be transferred");
      }
      const historical = options.db
        .prepare(
          `SELECT id, user_id, status
           FROM identity_connections historical
           WHERE installation_id = ? AND provider = ?
             AND external_tenant_id = ? AND external_subject = ?
             AND NOT EXISTS (
               SELECT 1 FROM identity_connections successor
               WHERE successor.replaces_connection_id = historical.id
             )
           ORDER BY historical.created_at_ms DESC, historical.id DESC
           LIMIT 1`
        )
        .get(installation.id, provider, externalTenantId, externalSubject) as
        | { id: string; user_id: string; status: "active" | "revoked" }
        | undefined;
      if (historical?.status === "active") throw new Error("External identity is already linked");

      const revalidateCompletionBoundary = (): number => {
        const boundaryNow = currentTime(clock);
        if (
          boundaryNow >= challenge.expires_at_ms ||
          boundaryNow >= challenge.auth_session_expires_at_ms
        ) {
          throw new Error("Link Challenge expired");
        }
        if (!authenticationSnapshotIsActive(actor)) {
          throw new Error("Link Challenge authentication session changed");
        }
        return boundaryNow;
      };

      if (input.identityCredential && identityBrokerKind) {
        const identityHandle = registerVerifiedCredentialHandle({
          actor,
          actorKind: "provider",
          provider,
          brokerKind: identityBrokerKind,
          authorityBinding: Object.freeze({
            kind: "identity-connection",
            userId: challenge.user_id,
            installationId: installation.id,
            installationRevision: installation.revision,
            externalTenantId,
            externalSubject,
            providerProofReplayDigest: proofReplayDigest,
          }),
          replaces: null,
          brokerProof: input.identityCredential.brokerProof,
          now: initiallyCheckedAtMs,
          beforePersist: revalidateCompletionBoundary,
        });
        identityHandleId = identityHandle.id;
        identityHandleGeneration = identityHandle.generation;
      }
      // This is the last external-state validation before the authoritative
      // challenge consumption. If the broker path persisted a handle first,
      // throwing here rolls that insert and its ledger row back atomically.
      const completedAtMs = revalidateCompletionBoundary();
      const consumed = options.db
        .prepare(
          `UPDATE link_challenges
           SET status = 'consumed', version = version + 1, resolved_at_ms = ?,
               provider_proof_replay_digest = ?
           WHERE id = ? AND status = 'active' AND version = ?
             AND provider_proof_replay_digest IS NULL`
        )
        .run(completedAtMs, proofReplayDigest, challenge.id, challenge.version);
      if (consumed.changes !== 1) throw new Error("Link Challenge consumption was fenced");
      const connectionId = generatedId(idGenerator, "Identity Connection ID");
      options.db
        .prepare(
          `INSERT INTO identity_connections (
             id, user_id, provider, external_tenant_id, external_subject,
             installation_id, installation_revision,
             scopes_schema, scopes_json, scopes_digest,
             credential_handle_id, credential_handle_generation,
             link_challenge_id, provider_proof_replay_digest, replaces_connection_id,
             status, generation,
             updated_by_user_id, updated_by_user_generation,
             updated_by_auth_identity_id, updated_by_auth_identity_generation,
             created_at_ms, updated_at_ms, revoked_at_ms
           ) VALUES (
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 1,
             ?, ?, ?, ?, ?, ?, NULL
           )`
        )
        .run(
          connectionId,
          challenge.user_id,
          provider,
          externalTenantId,
          externalSubject,
          installation.id,
          installation.revision,
          requestedScopes.schema,
          requestedScopes.json,
          requestedScopes.digest,
          identityHandleId,
          identityHandleGeneration,
          challenge.id,
          proofReplayDigest,
          historical?.id ?? null,
          actor.userId,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          completedAtMs,
          completedAtMs
        );
      appendLedger({
        eventType: "link-challenge.consumed",
        actorKind: "provider",
        actor,
        resourceKind: "link-challenge",
        resourceId: challenge.id,
        resourceVersion: challenge.version + 1,
        teamId: installation.team_id,
        subjectUserId: challenge.user_id,
        provider,
        detail: {
          installationRevision: installation.revision,
          requestedScopesDigest: requestedScopes.digest,
          proofReplayDigest,
        },
        occurredAtMs: completedAtMs,
      });
      appendLedger({
        eventType: "identity-connection.created",
        actorKind: "provider",
        actor,
        resourceKind: "identity-connection",
        resourceId: connectionId,
        resourceVersion: 1,
        teamId: installation.team_id,
        subjectUserId: challenge.user_id,
        provider,
        detail: {
          scopesDigest: requestedScopes.digest,
          hasCredentialHandle: identityHandleId !== null,
          replacement: Boolean(historical),
        },
        occurredAtMs: completedAtMs,
      });
      return connectionView(
        requireRow(
          findConnection.get(connectionId) as ConnectionRow | undefined,
          "Identity Connection"
        )
      );
    }
  );

  const revokeIdentityConnection = options.db.transaction(
    (input: {
      actor: ConnectionActorSnapshot;
      connectionId: string;
      expectedGeneration: number;
    }): IdentityConnectionView => {
      const actor = resolveActor(input.actor);
      const connectionId = boundedIdentifier(input.connectionId, "Identity Connection ID", 300);
      const expectedGeneration = positiveVersion(
        input.expectedGeneration,
        "Identity Connection generation"
      );
      const connection = requireRow(
        findConnection.get(connectionId) as ConnectionRow | undefined,
        "Identity Connection"
      );
      if (connection.status !== "active" || connection.generation !== expectedGeneration) {
        throw new Error("Identity Connection revocation was fenced");
      }
      const installation = requireRow(
        findInstallation.get(connection.installation_id) as InstallationRow | undefined,
        "Channel Installation"
      );
      if (actor.userId !== connection.user_id) {
        throw new Error("Identity Connection owner authority is required");
      }
      const now = currentTime(clock);
      let revokedIdentityHandle: HandleRow | null = null;
      if (connection.credential_handle_id !== null) {
        const handle = requireRow(
          findHandle.get(connection.credential_handle_id) as HandleRow | undefined,
          "Identity Credential Handle"
        );
        if (
          handle.provider !== connection.provider ||
          handle.usage !== "identity-connection" ||
          (handle.status === "active" &&
            handle.generation !== connection.credential_handle_generation) ||
          (handle.status === "revoked" &&
            handle.generation !== connection.credential_handle_generation! + 1)
        ) {
          throw new Error("Identity Credential Handle snapshot is inconsistent");
        }
        requireHandleAuthorityBinding(
          handle,
          connection.provider,
          identityConnectionHandleAuthorityBinding(connection)
        );
        if (handle.status === "active") {
          revokeHandleRow(options.db, handle, actor, now);
          revokedIdentityHandle = handle;
        }
      }
      const updated = options.db
        .prepare(
          `UPDATE identity_connections
           SET status = 'revoked', generation = generation + 1,
               updated_by_user_id = ?, updated_by_user_generation = ?,
               updated_by_auth_identity_id = ?, updated_by_auth_identity_generation = ?,
               updated_at_ms = ?, revoked_at_ms = ?
           WHERE id = ? AND status = 'active' AND generation = ?`
        )
        .run(
          actor.userId,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          now,
          now,
          connectionId,
          expectedGeneration
        );
      if (updated.changes !== 1) throw new Error("Identity Connection revocation was fenced");
      if (revokedIdentityHandle) {
        appendLedger({
          eventType: "credential-handle.revoked",
          actorKind: "human",
          actor,
          resourceKind: "credential-handle",
          resourceId: revokedIdentityHandle.id,
          resourceVersion: revokedIdentityHandle.generation + 1,
          subjectUserId: connection.user_id,
          provider: connection.provider,
          detail: { status: "revoked", identityConnectionRevoked: true },
          occurredAtMs: now,
        });
      }
      appendLedger({
        eventType: "identity-connection.revoked",
        actorKind: "human",
        actor,
        resourceKind: "identity-connection",
        resourceId: connectionId,
        resourceVersion: expectedGeneration + 1,
        teamId: installation.team_id,
        subjectUserId: connection.user_id,
        provider: connection.provider,
        detail: { status: "revoked" },
        occurredAtMs: now,
      });
      return connectionView(
        requireRow(
          findConnection.get(connectionId) as ConnectionRow | undefined,
          "Identity Connection"
        )
      );
    }
  );

  const createChannelBinding = options.db.transaction(
    (input: CreateChannelBindingInput): ChannelBindingView => {
      const actor = resolveActor(input.actor);
      const installationId = boundedIdentifier(
        input.installationId,
        "Channel Installation ID",
        300
      );
      const installation = requireActiveInstallation(findInstallation, installationId);
      const expectedInstallationRevision = positiveVersion(
        input.expectedInstallationRevision,
        "Channel Installation revision"
      );
      if (installation.revision !== expectedInstallationRevision) {
        throw new Error("Channel Installation revision is stale");
      }
      requireActiveInstallationCredentialHandle(findHandle, installation);
      const member = adminMembership(installation.team_id, actor);
      const sessionId = boundedIdentifier(input.sessionId, "Team Session ID", 300);
      const session = findSession.get(sessionId) as SessionRow | undefined;
      if (!session || session.team_id !== installation.team_id || session.status !== "active") {
        throw new Error("Active Team Session is required");
      }
      const kind = conversationKind(input.conversationKind);
      const externalConversationId = boundedIdentifier(
        input.externalConversationId,
        "external conversation ID",
        2048
      );
      const externalThreadId =
        kind === "thread"
          ? boundedIdentifier(input.externalThreadId, "external thread ID", 2048)
          : emptyExternalThread(input.externalThreadId);
      const inbound = canonicalInboundPolicy(input.inboundPolicy);
      const outbound = canonicalOutboundPolicy(input.outboundPolicy);
      const now = currentTime(clock);
      const bindingId = generatedId(idGenerator, "Channel Binding ID");
      options.db
        .prepare(
          `INSERT INTO channel_bindings (
             id, session_id, team_id, installation_id, installation_revision,
             provider, conversation_kind, external_conversation_id, external_thread_id,
             policy_schema, inbound_policy_json, inbound_policy_digest,
             outbound_policy_json, outbound_policy_digest,
             status, revision,
             created_by_user_id, created_under_membership_version,
             created_by_user_generation, created_by_auth_identity_id,
             created_by_auth_identity_generation,
             updated_by_user_id, updated_under_membership_version,
             updated_by_user_generation, updated_by_auth_identity_id,
             updated_by_auth_identity_generation,
             created_at_ms, updated_at_ms, revoked_at_ms
           ) VALUES (
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 1,
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL
           )`
        )
        .run(
          bindingId,
          sessionId,
          installation.team_id,
          installation.id,
          installation.revision,
          installation.provider,
          kind,
          externalConversationId,
          externalThreadId,
          CHANNEL_BINDING_POLICY_SCHEMA,
          inbound.json,
          inbound.digest,
          outbound.json,
          outbound.digest,
          actor.userId,
          member.version,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          actor.userId,
          member.version,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          now,
          now
        );
      appendLedger({
        eventType: "channel-binding.created",
        actorKind: "human",
        actor,
        resourceKind: "channel-binding",
        resourceId: bindingId,
        resourceVersion: 1,
        teamId: installation.team_id,
        sessionId,
        provider: installation.provider,
        detail: {
          inboundPolicyDigest: inbound.digest,
          outboundPolicyDigest: outbound.digest,
          installationRevision: installation.revision,
        },
        occurredAtMs: now,
      });
      return bindingView(
        requireRow(findBinding.get(bindingId) as BindingRow | undefined, "Channel Binding")
      );
    }
  );

  const updateChannelBinding = options.db.transaction(
    (input: {
      actor: ConnectionActorSnapshot;
      bindingId: string;
      expectedRevision: number;
      expectedInstallationRevision: number;
      inboundPolicy: ChannelInboundPolicy;
      outboundPolicy: ChannelOutboundPolicy;
    }): ChannelBindingView => {
      const actor = resolveActor(input.actor);
      const bindingId = boundedIdentifier(input.bindingId, "Channel Binding ID", 300);
      const expectedRevision = positiveVersion(input.expectedRevision, "Channel Binding revision");
      const binding = requireRow(
        findBinding.get(bindingId) as BindingRow | undefined,
        "Channel Binding"
      );
      if (binding.status !== "active" || binding.revision !== expectedRevision) {
        throw new Error("Channel Binding update was fenced");
      }
      const session = findSession.get(binding.session_id) as SessionRow | undefined;
      if (!session || session.team_id !== binding.team_id || session.status !== "active") {
        throw new Error("Active Team Session is required");
      }
      const installation = requireActiveInstallation(findInstallation, binding.installation_id);
      if (installation.team_id !== binding.team_id || installation.provider !== binding.provider) {
        throw new Error("Channel Binding authority snapshot is inconsistent");
      }
      const expectedInstallationRevision = positiveVersion(
        input.expectedInstallationRevision,
        "Channel Installation revision"
      );
      if (installation.revision !== expectedInstallationRevision) {
        throw new Error("Channel Installation revision is stale");
      }
      requireActiveInstallationCredentialHandle(findHandle, installation);
      const member = adminMembership(binding.team_id, actor);
      const inbound = canonicalInboundPolicy(input.inboundPolicy);
      const outbound = canonicalOutboundPolicy(input.outboundPolicy);
      const now = currentTime(clock);
      const updated = options.db
        .prepare(
          `UPDATE channel_bindings
           SET installation_revision = ?, policy_schema = ?,
               inbound_policy_json = ?, inbound_policy_digest = ?,
               outbound_policy_json = ?, outbound_policy_digest = ?,
               revision = revision + 1,
               updated_by_user_id = ?, updated_under_membership_version = ?,
               updated_by_user_generation = ?, updated_by_auth_identity_id = ?,
               updated_by_auth_identity_generation = ?, updated_at_ms = ?
           WHERE id = ? AND status = 'active' AND revision = ?`
        )
        .run(
          installation.revision,
          CHANNEL_BINDING_POLICY_SCHEMA,
          inbound.json,
          inbound.digest,
          outbound.json,
          outbound.digest,
          actor.userId,
          member.version,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          now,
          bindingId,
          expectedRevision
        );
      if (updated.changes !== 1) throw new Error("Channel Binding update was fenced");
      appendLedger({
        eventType: "channel-binding.updated",
        actorKind: "human",
        actor,
        resourceKind: "channel-binding",
        resourceId: bindingId,
        resourceVersion: expectedRevision + 1,
        teamId: binding.team_id,
        sessionId: binding.session_id,
        provider: binding.provider,
        detail: {
          inboundPolicyDigest: inbound.digest,
          outboundPolicyDigest: outbound.digest,
          installationRevision: installation.revision,
        },
        occurredAtMs: now,
      });
      return bindingView(
        requireRow(findBinding.get(bindingId) as BindingRow | undefined, "Channel Binding")
      );
    }
  );

  const revokeChannelBinding = options.db.transaction(
    (input: {
      actor: ConnectionActorSnapshot;
      bindingId: string;
      expectedRevision: number;
    }): ChannelBindingView => {
      const actor = resolveActor(input.actor);
      const bindingId = boundedIdentifier(input.bindingId, "Channel Binding ID", 300);
      const expectedRevision = positiveVersion(input.expectedRevision, "Channel Binding revision");
      const binding = requireRow(
        findBinding.get(bindingId) as BindingRow | undefined,
        "Channel Binding"
      );
      if (binding.status !== "active" || binding.revision !== expectedRevision) {
        throw new Error("Channel Binding revocation was fenced");
      }
      const member = adminMembership(binding.team_id, actor);
      const now = currentTime(clock);
      const updated = options.db
        .prepare(
          `UPDATE channel_bindings
           SET status = 'revoked', revision = revision + 1,
               updated_by_user_id = ?, updated_under_membership_version = ?,
               updated_by_user_generation = ?, updated_by_auth_identity_id = ?,
               updated_by_auth_identity_generation = ?, updated_at_ms = ?, revoked_at_ms = ?
           WHERE id = ? AND status = 'active' AND revision = ?`
        )
        .run(
          actor.userId,
          member.version,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          now,
          now,
          bindingId,
          expectedRevision
        );
      if (updated.changes !== 1) throw new Error("Channel Binding revocation was fenced");
      appendLedger({
        eventType: "channel-binding.revoked",
        actorKind: "human",
        actor,
        resourceKind: "channel-binding",
        resourceId: bindingId,
        resourceVersion: expectedRevision + 1,
        teamId: binding.team_id,
        sessionId: binding.session_id,
        provider: binding.provider,
        detail: { status: "revoked" },
        occurredAtMs: now,
      });
      return bindingView(
        requireRow(findBinding.get(bindingId) as BindingRow | undefined, "Channel Binding")
      );
    }
  );

  const revokeChannelInstallation = options.db.transaction(
    (input: {
      actor: ConnectionActorSnapshot;
      installationId: string;
      expectedRevision: number;
    }): ChannelInstallationView => {
      const actor = resolveActor(input.actor);
      const installationId = boundedIdentifier(
        input.installationId,
        "Channel Installation ID",
        300
      );
      const expectedRevision = positiveVersion(
        input.expectedRevision,
        "Channel Installation revision"
      );
      const installation = requireActiveInstallation(findInstallation, installationId);
      if (installation.revision !== expectedRevision) {
        throw new Error("Channel Installation revocation was fenced");
      }
      const member = adminMembership(installation.team_id, actor);
      const now = currentTime(clock);
      const installationHandle = requireRow(
        findHandle.get(installation.credential_handle_id) as HandleRow | undefined,
        "Installation Credential Handle"
      );
      if (
        installationHandle.provider !== installation.provider ||
        installationHandle.usage !== "installation" ||
        (installationHandle.status === "active" &&
          installationHandle.generation !== installation.credential_handle_generation) ||
        (installationHandle.status === "revoked" &&
          installationHandle.generation !== installation.credential_handle_generation + 1)
      ) {
        throw new Error("Installation Credential Handle snapshot is inconsistent");
      }
      requireHandleAuthorityBinding(
        installationHandle,
        installation.provider,
        installationHandleAuthorityBinding(installation)
      );

      // Revoke Team-owned bindings and bounded active challenges atomically.
      // User-owned Identity Connections remain immutable under Team admin
      // authority and become ineffective because resolution joins the active
      // Installation snapshot.
      const bindings = options.db
        .prepare(
          `SELECT ${BINDING_COLUMNS} FROM channel_bindings WHERE installation_id = ? AND status = 'active'`
        )
        .all(installationId) as BindingRow[];
      for (const binding of bindings) {
        options.db
          .prepare(
            `UPDATE channel_bindings
             SET status = 'revoked', revision = revision + 1,
                 updated_by_user_id = ?, updated_under_membership_version = ?,
                 updated_by_user_generation = ?, updated_by_auth_identity_id = ?,
                 updated_by_auth_identity_generation = ?, updated_at_ms = ?, revoked_at_ms = ?
             WHERE id = ? AND status = 'active' AND revision = ?`
          )
          .run(
            actor.userId,
            member.version,
            actor.userGeneration,
            actor.authIdentityId,
            actor.authIdentityGeneration,
            now,
            now,
            binding.id,
            binding.revision
          );
        appendLedger({
          eventType: "channel-binding.revoked",
          actorKind: "human",
          actor,
          resourceKind: "channel-binding",
          resourceId: binding.id,
          resourceVersion: binding.revision + 1,
          teamId: binding.team_id,
          sessionId: binding.session_id,
          provider: binding.provider,
          detail: { status: "revoked", installationRevoked: true },
          occurredAtMs: now,
        });
      }
      revokeActiveChallengesForInstallation({
        installation,
        actor,
        now,
        reason: "installationRevoked",
      });
      const updated = options.db
        .prepare(
          `UPDATE channel_installations
           SET status = 'revoked', revision = revision + 1,
               updated_by_user_id = ?, updated_under_membership_version = ?,
               updated_by_user_generation = ?, updated_by_auth_identity_id = ?,
               updated_by_auth_identity_generation = ?, updated_at_ms = ?, revoked_at_ms = ?
           WHERE id = ? AND status = 'active' AND revision = ?`
        )
        .run(
          actor.userId,
          member.version,
          actor.userGeneration,
          actor.authIdentityId,
          actor.authIdentityGeneration,
          now,
          now,
          installationId,
          expectedRevision
        );
      if (updated.changes !== 1) throw new Error("Channel Installation revocation was fenced");
      if (installationHandle.status === "active") {
        revokeHandleRow(options.db, installationHandle, actor, now);
        appendLedger({
          eventType: "credential-handle.revoked",
          actorKind: "human",
          actor,
          resourceKind: "credential-handle",
          resourceId: installationHandle.id,
          resourceVersion: installationHandle.generation + 1,
          provider: installationHandle.provider,
          detail: { status: "revoked", installationRevoked: true },
          occurredAtMs: now,
        });
      }
      appendLedger({
        eventType: "channel-installation.revoked",
        actorKind: "human",
        actor,
        resourceKind: "channel-installation",
        resourceId: installationId,
        resourceVersion: expectedRevision + 1,
        teamId: installation.team_id,
        provider: installation.provider,
        detail: { status: "revoked" },
        occurredAtMs: now,
      });
      return installationView(
        requireRow(
          findInstallation.get(installationId) as InstallationRow | undefined,
          "Channel Installation"
        )
      );
    }
  );

  const resolveInboundAttribution = options.db.transaction(
    (input: {
      action: "comment" | "directive";
      provider: ConnectionProvider;
      installationId: string;
      expectedInstallationRevision: number;
      bindingId: string;
      expectedBindingRevision: number;
      externalTenantId: string;
      externalSubject: string;
      conversationKind: "channel" | "thread" | "topic";
      externalConversationId: string;
      externalThreadId?: string;
    }): InboundAttributionResolution | null => {
      const action = inboundConnectionAction(input.action);
      const provider = connectionProvider(input.provider);
      const installationId = boundedIdentifier(
        input.installationId,
        "Channel Installation ID",
        300
      );
      const expectedInstallationRevision = positiveVersion(
        input.expectedInstallationRevision,
        "Channel Installation revision"
      );
      const bindingId = boundedIdentifier(input.bindingId, "Channel Binding ID", 300);
      const expectedBindingRevision = positiveVersion(
        input.expectedBindingRevision,
        "Channel Binding revision"
      );
      const externalTenantId = boundedIdentifier(input.externalTenantId, "external tenant ID");
      const externalSubject = boundedIdentifier(input.externalSubject, "external provider subject");
      const kind = conversationKind(input.conversationKind);
      const externalConversationId = boundedIdentifier(
        input.externalConversationId,
        "external conversation ID",
        2048
      );
      const externalThreadId =
        kind === "thread"
          ? boundedIdentifier(input.externalThreadId, "external thread ID", 2048)
          : emptyExternalThread(input.externalThreadId);

      const installation = findInstallation.get(installationId) as InstallationRow | undefined;
      if (
        !installation ||
        installation.status !== "active" ||
        installation.revision !== expectedInstallationRevision ||
        installation.provider !== provider ||
        installation.external_tenant_id !== externalTenantId
      ) {
        return null;
      }
      const installationHandle = findHandle.get(installation.credential_handle_id) as
        | HandleRow
        | undefined;
      if (
        !isActiveHandleSnapshot(
          installationHandle,
          installation.credential_handle_generation,
          provider,
          "installation"
        ) ||
        !matchesHandleAuthorityBinding(
          installationHandle,
          provider,
          installationHandleAuthorityBinding(installation)
        )
      ) {
        return null;
      }
      const binding = findBinding.get(bindingId) as BindingRow | undefined;
      if (
        !binding ||
        binding.status !== "active" ||
        binding.revision !== expectedBindingRevision ||
        binding.installation_id !== installation.id ||
        binding.installation_revision !== installation.revision ||
        binding.provider !== provider ||
        binding.conversation_kind !== kind ||
        binding.external_conversation_id !== externalConversationId ||
        binding.external_thread_id !== externalThreadId
      ) {
        return null;
      }
      const session = findSession.get(binding.session_id) as SessionRow | undefined;
      if (!isActiveSessionSnapshot(session, binding.team_id, installation.team_id)) return null;
      const connection = findActiveConnectionByExternalIdentity.get(
        installation.id,
        provider,
        externalTenantId,
        externalSubject
      ) as ConnectionRow | undefined;
      if (
        !connection ||
        connection.installation_id !== installation.id ||
        connection.installation_revision !== installation.revision ||
        !findActiveUser.get(connection.user_id)
      ) {
        return null;
      }
      if (connection.credential_handle_id !== null) {
        const identityHandle = findHandle.get(connection.credential_handle_id) as
          | HandleRow
          | undefined;
        if (
          connection.credential_handle_generation === null ||
          !isActiveHandleSnapshot(
            identityHandle,
            connection.credential_handle_generation,
            provider,
            "identity-connection"
          ) ||
          !matchesHandleAuthorityBinding(
            identityHandle,
            provider,
            identityConnectionHandleAuthorityBinding(connection)
          )
        ) {
          return null;
        }
      }
      try {
        const installationSnapshot = installationView(installation);
        const bindingSnapshot = bindingView(binding);
        const connectionSnapshot = connectionView(connection);
        if (
          bindingSnapshot.inboundPolicy.mode === "notifications-only" ||
          (action === "directive" &&
            bindingSnapshot.inboundPolicy.mode !== "comments-and-directives")
        ) {
          return null;
        }
        return Object.freeze({
          direction: "inbound" as const,
          action,
          provider,
          session: sessionFence(session!),
          installation: Object.freeze({
            id: installationSnapshot.id,
            revision: installationSnapshot.revision,
            externalTenantId: installationSnapshot.externalTenantId,
            externalAppId: installationSnapshot.externalAppId,
            credentialHandleId: installationSnapshot.credentialHandleId,
            credentialHandleGeneration: installationSnapshot.credentialHandleGeneration,
          }),
          binding: Object.freeze({
            id: bindingSnapshot.id,
            revision: bindingSnapshot.revision,
            conversationKind: bindingSnapshot.conversationKind,
            externalConversationId: bindingSnapshot.externalConversationId,
            externalThreadId: bindingSnapshot.externalThreadId,
            inboundPolicy: bindingSnapshot.inboundPolicy,
            inboundPolicyDigest: bindingSnapshot.inboundPolicyDigest,
          }),
          identity: Object.freeze({
            connectionId: connectionSnapshot.id,
            connectionGeneration: connectionSnapshot.generation,
            userId: connectionSnapshot.userId,
            externalSubject: connectionSnapshot.externalSubject,
            scopes: connectionSnapshot.scopes,
            scopesDigest: connectionSnapshot.scopesDigest,
            credentialHandleId: connectionSnapshot.credentialHandleId,
            credentialHandleGeneration: connectionSnapshot.credentialHandleGeneration,
          }),
        });
      } catch {
        return null;
      }
    }
  );

  const resolveOutboundBinding = options.db.transaction(
    (input: {
      bindingId: string;
      expectedBindingRevision: number;
      expectedInstallationRevision: number;
      messageKind: "mention" | "session-message";
      includesArtifacts: boolean;
    }): OutboundBindingResolution | null => {
      const messageKind = outboundMessageKind(input.messageKind);
      if (typeof input.includesArtifacts !== "boolean") {
        throw new TypeError("Outbound artifact presence is invalid");
      }
      const bindingId = boundedIdentifier(input.bindingId, "Channel Binding ID", 300);
      const expectedBindingRevision = positiveVersion(
        input.expectedBindingRevision,
        "Channel Binding revision"
      );
      const expectedInstallationRevision = positiveVersion(
        input.expectedInstallationRevision,
        "Channel Installation revision"
      );
      const binding = findBinding.get(bindingId) as BindingRow | undefined;
      if (!binding || binding.status !== "active" || binding.revision !== expectedBindingRevision) {
        return null;
      }
      const installation = findInstallation.get(binding.installation_id) as
        | InstallationRow
        | undefined;
      if (
        !installation ||
        installation.status !== "active" ||
        installation.revision !== expectedInstallationRevision ||
        binding.installation_revision !== installation.revision ||
        binding.team_id !== installation.team_id ||
        binding.provider !== installation.provider
      ) {
        return null;
      }
      const installationHandle = findHandle.get(installation.credential_handle_id) as
        | HandleRow
        | undefined;
      if (
        !isActiveHandleSnapshot(
          installationHandle,
          installation.credential_handle_generation,
          installation.provider,
          "installation"
        ) ||
        !matchesHandleAuthorityBinding(
          installationHandle,
          installation.provider,
          installationHandleAuthorityBinding(installation)
        )
      ) {
        return null;
      }
      const session = findSession.get(binding.session_id) as SessionRow | undefined;
      if (!isActiveSessionSnapshot(session, binding.team_id, installation.team_id)) return null;
      try {
        const installationSnapshot = installationView(installation);
        const bindingSnapshot = bindingView(binding);
        if (
          bindingSnapshot.outboundPolicy.mode === "disabled" ||
          (bindingSnapshot.outboundPolicy.mode === "mentions" && messageKind !== "mention") ||
          (input.includesArtifacts && !bindingSnapshot.outboundPolicy.allowArtifacts)
        ) {
          return null;
        }
        return Object.freeze({
          direction: "outbound" as const,
          messageKind,
          includesArtifacts: input.includesArtifacts,
          provider: installationSnapshot.provider,
          session: sessionFence(session!),
          installation: Object.freeze({
            id: installationSnapshot.id,
            revision: installationSnapshot.revision,
            externalTenantId: installationSnapshot.externalTenantId,
            externalAppId: installationSnapshot.externalAppId,
            credentialHandleId: installationSnapshot.credentialHandleId,
            credentialHandleGeneration: installationSnapshot.credentialHandleGeneration,
          }),
          binding: Object.freeze({
            id: bindingSnapshot.id,
            revision: bindingSnapshot.revision,
            conversationKind: bindingSnapshot.conversationKind,
            externalConversationId: bindingSnapshot.externalConversationId,
            externalThreadId: bindingSnapshot.externalThreadId,
            outboundPolicy: bindingSnapshot.outboundPolicy,
            outboundPolicyDigest: bindingSnapshot.outboundPolicyDigest,
          }),
        });
      } catch {
        return null;
      }
    }
  );

  const authority: ConnectionAuthority = {
    createChannelInstallation: (input) => createChannelInstallation.immediate(input),
    rotateChannelInstallationCredential: (input) =>
      rotateChannelInstallationCredential.immediate(input),
    revokeChannelInstallation: (input) => revokeChannelInstallation.immediate(input),
    issueLinkChallenge: (input) => issueLinkChallenge.immediate(input),
    completeLinkChallenge: (input) => completeLinkChallenge.immediate(input),
    revokeIdentityConnection: (input) => revokeIdentityConnection.immediate(input),
    createChannelBinding: (input) => createChannelBinding.immediate(input),
    updateChannelBinding: (input) => updateChannelBinding.immediate(input),
    revokeChannelBinding: (input) => revokeChannelBinding.immediate(input),
    resolveInboundAttribution: (input) => resolveInboundAttribution.deferred(input),
    resolveOutboundBinding: (input) => resolveOutboundBinding.deferred(input),
  };
  return Object.freeze(authority);
}

function requireStoredActor(db: Database.Database, challenge: ChallengeRow): ResolvedActor {
  const row = db
    .prepare(
      `SELECT user.id AS user_id, user.username,
              user.generation AS user_generation,
              identity.id AS auth_identity_id,
              identity.provider AS auth_provider, identity.subject AS auth_subject,
              identity.generation AS auth_identity_generation
       FROM users user
       JOIN auth_identities identity ON identity.user_id = user.id
       WHERE user.id = ? AND user.generation = ? AND user.status = 'active'
         AND identity.id = ? AND identity.generation = ? AND identity.status = 'active'`
    )
    .get(
      challenge.user_id,
      challenge.user_generation,
      challenge.auth_identity_id,
      challenge.auth_identity_generation
    ) as ActorRow | undefined;
  if (!row) throw new Error("Link Challenge authentication identity changed");
  return Object.freeze({
    userId: row.user_id,
    username: row.username,
    userGeneration: row.user_generation,
    authProvider: row.auth_provider,
    authSubject: row.auth_subject,
    authIdentityId: row.auth_identity_id,
    authIdentityGeneration: row.auth_identity_generation,
    authenticatedAtMs: challenge.authenticated_at_ms,
    credentialIssuedAtMs: challenge.auth_session_issued_at_ms,
    credentialExpiresAtMs: challenge.auth_session_expires_at_ms,
    credentialJtiDigest: challenge.auth_session_jti_digest,
    device:
      challenge.auth_session_provenance === "paired-device"
        ? {
            provenance: "paired-device" as const,
            id: requireStoredDeviceId(challenge.auth_session_device_id),
          }
        : { provenance: "browser" as const },
  });
}

function revokeHandleRow(
  db: Database.Database,
  handle: HandleRow,
  actor: ResolvedActor,
  now: number
): void {
  const result = db
    .prepare(
      `UPDATE credential_handles
       SET status = 'revoked', generation = generation + 1,
           updated_by_user_id = ?, updated_by_user_generation = ?,
           updated_by_auth_identity_id = ?, updated_by_auth_identity_generation = ?,
           updated_at_ms = ?, revoked_at_ms = ?
       WHERE id = ? AND status = 'active' AND generation = ?`
    )
    .run(
      actor.userId,
      actor.userGeneration,
      actor.authIdentityId,
      actor.authIdentityGeneration,
      now,
      now,
      handle.id,
      handle.generation
    );
  if (result.changes !== 1) throw new Error("Credential Handle revocation was fenced");
}

function requireActiveHandle(
  statement: Database.Statement,
  handleId: string,
  generation: number,
  provider: ConnectionProvider,
  usage: CredentialHandleUsage
): HandleRow {
  const row = statement.get(handleId) as HandleRow | undefined;
  if (
    !row ||
    row.status !== "active" ||
    row.generation !== generation ||
    row.provider !== provider ||
    row.usage !== usage
  ) {
    throw new Error("Credential Handle snapshot is unavailable");
  }
  return row;
}

function requireActiveInstallationCredentialHandle(
  statement: Database.Statement,
  installation: InstallationRow
): HandleRow {
  const row = requireActiveHandle(
    statement,
    installation.credential_handle_id,
    installation.credential_handle_generation,
    installation.provider,
    "installation"
  );
  requireHandleAuthorityBinding(
    row,
    installation.provider,
    installationHandleAuthorityBinding(installation)
  );
  return row;
}

function requireActiveInstallation(
  statement: Database.Statement,
  installationId: string
): InstallationRow {
  const row = statement.get(installationId) as InstallationRow | undefined;
  if (!row || row.status !== "active") throw new Error("Channel Installation is unavailable");
  return row;
}

function storedStringSet(schema: number, json: string, digest: string, label: string) {
  if (schema !== CONNECTION_SET_SCHEMA || sha256(json) !== digest) {
    throw new Error(`${label} failed integrity validation`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error(`${label} failed integrity validation`);
  }
  if (!Array.isArray(parsed)) throw new Error(`${label} failed integrity validation`);
  const canonical = canonicalStringSet(parsed, label);
  if (canonical.json !== json || canonical.digest !== digest) {
    throw new Error(`${label} is not canonical`);
  }
  return canonical;
}

function installationView(row: InstallationRow): ChannelInstallationView {
  const scopes = storedStringSet(
    row.reviewed_scopes_schema,
    row.reviewed_scopes_json,
    row.reviewed_scopes_digest,
    "Channel Installation reviewed scopes"
  );
  const capabilities = storedStringSet(
    row.capabilities_schema,
    row.capabilities_json,
    row.capabilities_digest,
    "Channel Installation capabilities"
  );
  return Object.freeze({
    id: row.id,
    teamId: row.team_id,
    provider: row.provider,
    externalTenantId: row.external_tenant_id,
    externalAppId: row.external_app_id,
    credentialHandleId: row.credential_handle_id,
    credentialHandleGeneration: row.credential_handle_generation,
    reviewedScopes: scopes.values,
    reviewedScopesDigest: scopes.digest,
    capabilities: capabilities.values,
    capabilitiesDigest: capabilities.digest,
    status: row.status,
    revision: row.revision,
    createdAtMs: row.created_at_ms,
    updatedAtMs: row.updated_at_ms,
    revokedAtMs: row.revoked_at_ms,
  });
}

function connectionView(row: ConnectionRow): IdentityConnectionView {
  const scopes = storedStringSet(
    row.scopes_schema,
    row.scopes_json,
    row.scopes_digest,
    "Identity Connection scopes"
  );
  return Object.freeze({
    id: row.id,
    userId: row.user_id,
    provider: row.provider,
    externalTenantId: row.external_tenant_id,
    externalSubject: row.external_subject,
    installationId: row.installation_id,
    installationRevision: row.installation_revision,
    scopes: scopes.values,
    scopesDigest: scopes.digest,
    credentialHandleId: row.credential_handle_id,
    credentialHandleGeneration: row.credential_handle_generation,
    status: row.status,
    generation: row.generation,
    createdAtMs: row.created_at_ms,
    updatedAtMs: row.updated_at_ms,
    revokedAtMs: row.revoked_at_ms,
  });
}

function bindingView(row: BindingRow): ChannelBindingView {
  if (row.policy_schema !== CHANNEL_BINDING_POLICY_SCHEMA) {
    throw new Error("Channel Binding policy schema is unsupported");
  }
  let inboundUnknown: unknown;
  let outboundUnknown: unknown;
  try {
    inboundUnknown = JSON.parse(row.inbound_policy_json);
    outboundUnknown = JSON.parse(row.outbound_policy_json);
  } catch {
    throw new Error("Channel Binding policy failed integrity validation");
  }
  const inbound = canonicalInboundPolicy(inboundUnknown as ChannelInboundPolicy);
  const outbound = canonicalOutboundPolicy(outboundUnknown as ChannelOutboundPolicy);
  if (
    inbound.json !== row.inbound_policy_json ||
    inbound.digest !== row.inbound_policy_digest ||
    outbound.json !== row.outbound_policy_json ||
    outbound.digest !== row.outbound_policy_digest
  ) {
    throw new Error("Channel Binding policy failed integrity validation");
  }
  return Object.freeze({
    id: row.id,
    sessionId: row.session_id,
    teamId: row.team_id,
    installationId: row.installation_id,
    installationRevision: row.installation_revision,
    provider: row.provider,
    conversationKind: row.conversation_kind,
    externalConversationId: row.external_conversation_id,
    externalThreadId: row.external_thread_id,
    inboundPolicy: inbound.value,
    inboundPolicyDigest: inbound.digest,
    outboundPolicy: outbound.value,
    outboundPolicyDigest: outbound.digest,
    status: row.status,
    revision: row.revision,
    createdAtMs: row.created_at_ms,
    updatedAtMs: row.updated_at_ms,
    revokedAtMs: row.revoked_at_ms,
  });
}

function generatedChallenge(randomBytes: (size: number) => Buffer): string {
  const suffix = randomBytes(32).toString("hex");
  if (!/^[0-9a-f]{64}$/.test(suffix)) {
    throw new Error("Link Challenge generator returned an invalid value");
  }
  return `txlc_v1_${suffix}`;
}

function generatedId(generator: () => string, label: string): string {
  return boundedIdentifier(generator(), label, 300);
}

function credentialHandleId(value: unknown): string {
  if (typeof value !== "string" || !/^txch_v1_[0-9a-f]{64}$/.test(value)) {
    throw new TypeError("Credential Handle ID is invalid");
  }
  return value;
}

function authenticationProvider(value: unknown): "local" | "google" | "password" {
  if (value !== "local" && value !== "google" && value !== "password") {
    throw new TypeError("Authentication provider is invalid");
  }
  return value;
}

function currentTime(clock: () => number): number {
  return safeTimestamp(clock(), "Connection authority clock");
}

function requireRow<T>(row: T | undefined, label: string): T {
  if (!row) throw new Error(`${label} not found`);
  return row;
}

function emptyExternalThread(value: unknown): string {
  if (value !== undefined && value !== "") {
    throw new TypeError("External thread ID is only valid for a thread binding");
  }
  return "";
}

function inboundConnectionAction(value: unknown): "comment" | "directive" {
  if (value !== "comment" && value !== "directive") {
    throw new TypeError("Inbound connection action is invalid");
  }
  return value;
}

function outboundMessageKind(value: unknown): "mention" | "session-message" {
  if (value !== "mention" && value !== "session-message") {
    throw new TypeError("Outbound message kind is invalid");
  }
  return value;
}

function sameHandleRegistrationExpectation(
  actual: VerifiedCredentialHandleRegistration,
  expected: Readonly<CredentialHandleRegistrationExpectation>
): boolean {
  try {
    if (
      connectionProvider(actual.provider) !== expected.provider ||
      credentialBrokerKind(actual.brokerKind) !== expected.brokerKind ||
      credentialHandleUsage(actual.usage) !== expected.usage ||
      credentialHandleAuthorityBindingDigest(actual.provider, actual.authorityBinding) !==
        credentialHandleAuthorityBindingDigest(expected.provider, expected.authorityBinding) ||
      JSON.stringify(normalizedHandleAuthorityBinding(actual.authorityBinding)) !==
        JSON.stringify(normalizedHandleAuthorityBinding(expected.authorityBinding))
    ) {
      return false;
    }
    if (expected.replaces === null) return actual.replaces === null;
    return (
      actual.replaces !== null &&
      credentialHandleId(actual.replaces.handleId) === expected.replaces.handleId &&
      positiveVersion(actual.replaces.generation, "replaced Credential Handle generation") ===
        expected.replaces.generation
    );
  } catch {
    return false;
  }
}

function sameProviderProofExpectation(
  actual: VerifiedProviderIdentity,
  expected: Readonly<ProviderProofExpectation>
): boolean {
  try {
    return (
      connectionProvider(actual.provider) === expected.provider &&
      boundedIdentifier(actual.externalTenantId, "external tenant ID") ===
        expected.externalTenantId &&
      boundedIdentifier(actual.externalAppId, "external application ID") ===
        expected.externalAppId &&
      boundedIdentifier(actual.installationId, "Channel Installation ID", 300) ===
        expected.installationId &&
      positiveVersion(actual.installationRevision, "Channel Installation revision") ===
        expected.installationRevision &&
      sha256Digest(actual.challengeDigest, "Link Challenge digest") === expected.challengeDigest &&
      sha256Digest(actual.requestedScopesDigest, "requested provider scopes digest") ===
        expected.requestedScopesDigest
    );
  } catch {
    return false;
  }
}

export function providerProofReplayDigest(input: {
  provider: ConnectionProvider;
  externalTenantId: string;
  externalAppId: string;
  proofReplayId: string;
}): string {
  const provider = connectionProvider(input.provider);
  const externalTenantId = boundedIdentifier(input.externalTenantId, "external tenant ID");
  const externalAppId = boundedIdentifier(input.externalAppId, "external application ID");
  const proofReplayId = boundedIdentifier(input.proofReplayId, "provider proof replay ID", 2048);
  return sha256(
    JSON.stringify({
      schema: 1,
      provider,
      externalTenantId,
      externalAppId,
      proofReplayId,
    })
  );
}

export function credentialBrokerReceiptDigest(input: {
  provider: ConnectionProvider;
  brokerKind: CredentialBrokerKind;
  receiptId: string;
}): string {
  const provider = connectionProvider(input.provider);
  const brokerKind = credentialBrokerKind(input.brokerKind);
  const receiptId = boundedIdentifier(input.receiptId, "Secret Broker registration receipt", 2048);
  return sha256(JSON.stringify({ schema: 1, provider, brokerKind, receiptId }));
}

function normalizedHandleAuthorityBinding(
  input: CredentialHandleAuthorityBinding
): CredentialHandleAuthorityBinding {
  if (input?.kind === "installation") {
    return Object.freeze({
      kind: "installation" as const,
      teamId: boundedIdentifier(input.teamId, "Credential Handle Team ID", 300),
      externalTenantId: boundedIdentifier(input.externalTenantId, "external tenant ID"),
      externalAppId: boundedIdentifier(input.externalAppId, "external application ID"),
    });
  }
  if (input?.kind === "identity-connection") {
    return Object.freeze({
      kind: "identity-connection" as const,
      userId: boundedIdentifier(input.userId, "Credential Handle User ID", 300),
      installationId: boundedIdentifier(
        input.installationId,
        "Credential Handle Installation ID",
        300
      ),
      installationRevision: positiveVersion(
        input.installationRevision,
        "Credential Handle Installation revision"
      ),
      externalTenantId: boundedIdentifier(input.externalTenantId, "external tenant ID"),
      externalSubject: boundedIdentifier(input.externalSubject, "external provider subject"),
      providerProofReplayDigest: sha256Digest(
        input.providerProofReplayDigest,
        "provider proof replay digest"
      ),
    });
  }
  throw new TypeError("Credential Handle authority binding is invalid");
}

function credentialHandleAuthorityBindingDigest(
  providerInput: unknown,
  bindingInput: CredentialHandleAuthorityBinding
): string {
  const provider = connectionProvider(providerInput);
  const binding = normalizedHandleAuthorityBinding(bindingInput);
  return sha256(JSON.stringify({ schema: 1, provider, binding }));
}

function handleAuthorityColumns(bindingInput: CredentialHandleAuthorityBinding) {
  const binding = normalizedHandleAuthorityBinding(bindingInput);
  if (binding.kind === "installation") {
    return Object.freeze({
      teamId: binding.teamId,
      userId: null,
      externalTenantId: binding.externalTenantId,
      externalAppId: binding.externalAppId,
      identityInstallationId: null,
      identityInstallationRevision: null,
      externalSubject: null,
      providerProofReplayDigest: null,
    });
  }
  return Object.freeze({
    teamId: null,
    userId: binding.userId,
    externalTenantId: binding.externalTenantId,
    externalAppId: null,
    identityInstallationId: binding.installationId,
    identityInstallationRevision: binding.installationRevision,
    externalSubject: binding.externalSubject,
    providerProofReplayDigest: binding.providerProofReplayDigest,
  });
}

function installationHandleAuthorityBinding(
  installation: InstallationRow
): CredentialHandleAuthorityBinding {
  return Object.freeze({
    kind: "installation",
    teamId: installation.team_id,
    externalTenantId: installation.external_tenant_id,
    externalAppId: installation.external_app_id,
  });
}

function identityConnectionHandleAuthorityBinding(
  connection: ConnectionRow
): CredentialHandleAuthorityBinding {
  return Object.freeze({
    kind: "identity-connection",
    userId: connection.user_id,
    installationId: connection.installation_id,
    installationRevision: connection.installation_revision,
    externalTenantId: connection.external_tenant_id,
    externalSubject: connection.external_subject,
    providerProofReplayDigest: connection.provider_proof_replay_digest,
  });
}

function matchesHandleAuthorityBinding(
  row: HandleRow,
  provider: ConnectionProvider,
  bindingInput: CredentialHandleAuthorityBinding
): boolean {
  try {
    const binding = normalizedHandleAuthorityBinding(bindingInput);
    const columns = handleAuthorityColumns(binding);
    return (
      row.authority_binding_digest === credentialHandleAuthorityBindingDigest(provider, binding) &&
      row.team_id === columns.teamId &&
      row.user_id === columns.userId &&
      row.external_tenant_id === columns.externalTenantId &&
      row.external_app_id === columns.externalAppId &&
      row.identity_installation_id === columns.identityInstallationId &&
      row.identity_installation_revision === columns.identityInstallationRevision &&
      row.external_subject === columns.externalSubject &&
      row.provider_proof_replay_digest === columns.providerProofReplayDigest
    );
  } catch {
    return false;
  }
}

function requireHandleAuthorityBinding(
  row: HandleRow,
  provider: ConnectionProvider,
  binding: CredentialHandleAuthorityBinding
): void {
  if (!matchesHandleAuthorityBinding(row, provider, binding)) {
    throw new Error("Credential Handle authority binding is unavailable");
  }
}

function authenticationSnapshot(actor: ResolvedActor): Readonly<StoredAuthenticationSnapshot> {
  return Object.freeze({
    userId: actor.userId,
    username: actor.username,
    userGeneration: actor.userGeneration,
    authProvider: actor.authProvider,
    authSubject: actor.authSubject,
    authIdentityId: actor.authIdentityId,
    authIdentityGeneration: actor.authIdentityGeneration,
    ...(actor.authenticatedAtMs === undefined
      ? {}
      : { authenticatedAtMs: actor.authenticatedAtMs }),
    credentialIssuedAtMs: actor.credentialIssuedAtMs,
    credentialExpiresAtMs: actor.credentialExpiresAtMs,
    credentialJtiDigest: actor.credentialJtiDigest,
    device: actor.device,
  });
}

function requireStoredDeviceId(value: string | null): string {
  if (value === null) throw new Error("Stored authentication device snapshot is invalid");
  return boundedIdentifier(value, "stored authentication device ID", 300);
}

function isActiveHandleSnapshot(
  row: HandleRow | undefined,
  generation: number,
  provider: ConnectionProvider,
  usage: CredentialHandleUsage
): row is HandleRow {
  return Boolean(
    row &&
    row.status === "active" &&
    row.generation === generation &&
    row.provider === provider &&
    row.usage === usage
  );
}

function isActiveSessionSnapshot(
  row: SessionRow | undefined,
  bindingTeamId: string,
  installationTeamId: string
): row is SessionRow {
  return Boolean(
    row &&
    row.status === "active" &&
    row.team_id === bindingTeamId &&
    row.team_id === installationTeamId
  );
}

function sessionFence(row: SessionRow) {
  return Object.freeze({
    id: row.id,
    teamId: row.team_id,
    accessRevision: positiveVersion(row.access_revision, "Team Session access revision"),
    steeringRevision: positiveVersion(row.steering_revision, "Team Session steering revision"),
    controlRevision: positiveVersion(row.control_revision, "Team Session control revision"),
    runtimeAuthorizationGeneration: positiveVersion(
      row.runtime_authorization_generation,
      "Team Session Runtime authorization generation"
    ),
  });
}
