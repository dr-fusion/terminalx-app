import type Database from "better-sqlite3";
import { secretBrokerExpectationDigest } from "./secret-broker-shared";
import type { ConnectionProvider, ConversationKind } from "./contracts";

/**
 * Read-only lookups for the webhook ingress and installation routes (Slice 8E
 * follow-up). These are routing snapshots only: every mutation and attribution
 * still revalidates through the connection authority's own transactional fences.
 */
export interface InstallationSnapshot {
  readonly id: string;
  readonly teamId: string;
  readonly provider: ConnectionProvider;
  readonly externalTenantId: string;
  readonly externalAppId: string;
  readonly credentialHandleId: string;
  readonly credentialHandleGeneration: number;
  readonly revision: number;
}

export interface BindingSnapshot {
  readonly id: string;
  readonly revision: number;
  readonly sessionId: string;
  readonly conversationKind: ConversationKind;
  readonly externalConversationId: string;
  readonly externalThreadId: string;
  readonly inboundPolicy: {
    mode: "comments-only" | "comments-and-directives" | "notifications-only";
    requireLinkedIdentity: boolean;
  };
}

interface InstallationRow {
  id: string;
  team_id: string;
  provider: ConnectionProvider;
  external_tenant_id: string;
  external_app_id: string;
  credential_handle_id: string;
  credential_handle_generation: number;
  revision: number;
}

interface BindingRow {
  id: string;
  revision: number;
  session_id: string;
  conversation_kind: ConversationKind;
  external_conversation_id: string;
  external_thread_id: string;
  inbound_policy_json: string;
}

const INSTALLATION_COLUMNS = `id, team_id, provider, external_tenant_id, external_app_id,
  credential_handle_id, credential_handle_generation, revision`;

export function findActiveInstallationById(
  db: Database.Database,
  installationId: string,
  provider: ConnectionProvider
): InstallationSnapshot | null {
  const row = db
    .prepare(
      `SELECT ${INSTALLATION_COLUMNS} FROM channel_installations
       WHERE id = ? AND provider = ? AND status = 'active'`
    )
    .get(installationId, provider) as InstallationRow | undefined;
  return row ? toInstallation(row) : null;
}

export function findActiveSlackInstallationByTenant(
  db: Database.Database,
  externalTenantId: string,
  externalAppId: string | null
): InstallationSnapshot | null {
  const row = (
    externalAppId === null
      ? db
          .prepare(
            `SELECT ${INSTALLATION_COLUMNS} FROM channel_installations
             WHERE provider = 'slack' AND external_tenant_id = ? AND status = 'active'
             LIMIT 1`
          )
          .get(externalTenantId)
      : db
          .prepare(
            `SELECT ${INSTALLATION_COLUMNS} FROM channel_installations
             WHERE provider = 'slack' AND external_tenant_id = ? AND external_app_id = ?
               AND status = 'active'`
          )
          .get(externalTenantId, externalAppId)
  ) as InstallationRow | undefined;
  return row ? toInstallation(row) : null;
}

export function listActiveSlackInstallations(db: Database.Database): InstallationSnapshot[] {
  const rows = db
    .prepare(
      `SELECT ${INSTALLATION_COLUMNS} FROM channel_installations
       WHERE provider = 'slack' AND status = 'active'
       ORDER BY id LIMIT 64`
    )
    .all() as InstallationRow[];
  return rows.map(toInstallation);
}

export function findActiveBindingForConversation(
  db: Database.Database,
  input: {
    installationId: string;
    conversationKind: ConversationKind;
    externalConversationId: string;
    externalThreadId: string;
  }
): BindingSnapshot | null {
  // Prefer an exact thread/topic binding, then fall back to the channel binding
  // for the same conversation so a threaded reply still routes.
  const rows = db
    .prepare(
      `SELECT id, revision, session_id, conversation_kind, external_conversation_id,
              external_thread_id, inbound_policy_json
       FROM channel_bindings
       WHERE installation_id = ? AND external_conversation_id = ? AND status = 'active'
       ORDER BY revision DESC LIMIT 16`
    )
    .all(input.installationId, input.externalConversationId) as BindingRow[];
  const exact = rows.find(
    (row) =>
      row.conversation_kind === input.conversationKind &&
      row.external_thread_id === input.externalThreadId
  );
  const fallback = rows.find(
    (row) => row.conversation_kind === "channel" && row.external_thread_id === ""
  );
  const chosen = exact ?? fallback;
  if (!chosen) return null;
  let inboundPolicy: BindingSnapshot["inboundPolicy"];
  try {
    inboundPolicy = JSON.parse(chosen.inbound_policy_json) as BindingSnapshot["inboundPolicy"];
  } catch {
    return null;
  }
  return Object.freeze({
    id: chosen.id,
    revision: chosen.revision,
    sessionId: chosen.session_id,
    conversationKind: chosen.conversation_kind,
    externalConversationId: chosen.external_conversation_id,
    externalThreadId: chosen.external_thread_id,
    inboundPolicy,
  });
}

/**
 * The installation credential's broker `expectationDigest`, recomputed from the
 * installation snapshot. It keys the broker-side webhook signing secret (Slack)
 * and matches the digest bound at credential acquisition time.
 */
export function installationCredentialExpectationDigest(
  installation: InstallationSnapshot
): string {
  return secretBrokerExpectationDigest({
    provider: installation.provider,
    brokerKind: "oauth-envelope",
    usage: "installation",
    authorityBinding: Object.freeze({
      kind: "installation",
      teamId: installation.teamId,
      externalTenantId: installation.externalTenantId,
      externalAppId: installation.externalAppId,
    }),
    replaces: null,
  });
}

function toInstallation(row: InstallationRow): InstallationSnapshot {
  return Object.freeze({
    id: row.id,
    teamId: row.team_id,
    provider: row.provider,
    externalTenantId: row.external_tenant_id,
    externalAppId: row.external_app_id,
    credentialHandleId: row.credential_handle_id,
    credentialHandleGeneration: row.credential_handle_generation,
    revision: row.revision,
  });
}
