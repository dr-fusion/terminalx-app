import type Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { createWebhookDeliveryDedup, deliveryDigest } from "@/lib/connections/webhook-dedup";

describe("provider webhook delivery dedup (schema v14)", () => {
  let database: TeamSessionDatabase | undefined;
  afterEach(() => {
    database?.close();
    database = undefined;
  });

  function setup() {
    const db = openTeamSessionDatabase({ filename: ":memory:" });
    database = db;
    seedInstallation(db.db);
    return createWebhookDeliveryDedup(db.db);
  }

  it("records a first delivery and drops the exact replay", () => {
    const dedup = setup();
    expect(
      dedup.hasDelivery({ installationId: "inst-1", provider: "telegram", replayId: "100" })
    ).toBe(false);
    expect(
      dedup.recordDelivery({
        installationId: "inst-1",
        provider: "telegram",
        replayId: "100",
        monotonicOrdinal: 100,
        receivedAtMs: 1,
      })
    ).toEqual({ recorded: true });
    // Re-delivery of the same update_id is a no-op (dropped-replay).
    expect(
      dedup.hasDelivery({ installationId: "inst-1", provider: "telegram", replayId: "100" })
    ).toBe(true);
    expect(
      dedup.recordDelivery({
        installationId: "inst-1",
        provider: "telegram",
        replayId: "100",
        monotonicOrdinal: 100,
        receivedAtMs: 2,
      })
    ).toEqual({ recorded: false });
  });

  it("scopes dedup per installation and tracks the monotonic ordinal", () => {
    const dedup = setup();
    seedSecondInstallation(database!.db);
    dedup.recordDelivery({
      installationId: "inst-1",
      provider: "telegram",
      replayId: "50",
      monotonicOrdinal: 50,
      receivedAtMs: 1,
    });
    // Same replay id under a different installation is a distinct delivery.
    expect(
      dedup.hasDelivery({ installationId: "inst-2", provider: "telegram", replayId: "50" })
    ).toBe(false);
    dedup.recordDelivery({
      installationId: "inst-1",
      provider: "telegram",
      replayId: "77",
      monotonicOrdinal: 77,
      receivedAtMs: 2,
    });
    expect(dedup.latestOrdinal("inst-1", "telegram")).toBe(77);
    expect(dedup.latestOrdinal("inst-2", "telegram")).toBeNull();
  });

  it("dedups Slack event ids without an ordinal", () => {
    const dedup = setup();
    expect(
      dedup.recordDelivery({
        installationId: "inst-1",
        provider: "slack",
        replayId: "Ev123",
        receivedAtMs: 1,
      })
    ).toEqual({ recorded: true });
    expect(
      dedup.recordDelivery({
        installationId: "inst-1",
        provider: "slack",
        replayId: "Ev123",
        receivedAtMs: 2,
      })
    ).toEqual({ recorded: false });
    expect(dedup.latestOrdinal("inst-1", "slack")).toBeNull();
  });

  it("stores only a digest of the replay id, never the raw value", () => {
    const dedup = setup();
    dedup.recordDelivery({
      installationId: "inst-1",
      provider: "slack",
      replayId: "Ev-SENSITIVE",
      receivedAtMs: 1,
    });
    const rows = database!.db.prepare("SELECT * FROM provider_webhook_deliveries").all();
    expect(JSON.stringify(rows)).not.toContain("Ev-SENSITIVE");
    expect(JSON.stringify(rows)).toContain(deliveryDigest("slack", "inst-1", "Ev-SENSITIVE"));
  });

  it("is immutable: update and delete are rejected by triggers", () => {
    const dedup = setup();
    dedup.recordDelivery({
      installationId: "inst-1",
      provider: "slack",
      replayId: "Ev1",
      receivedAtMs: 1,
    });
    expect(() =>
      database!.db.prepare("UPDATE provider_webhook_deliveries SET received_at_ms = 9").run()
    ).toThrow(/immutable/);
    expect(() => database!.db.prepare("DELETE FROM provider_webhook_deliveries").run()).toThrow(
      /immutable/
    );
  });
});

function seedInstallation(db: Database.Database): void {
  db.exec(`
    INSERT INTO users (id, username, display_name, legacy_role, status, generation,
      created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms)
      VALUES ('user-1', 'alice', 'Alice', 'admin', 'active', 1, 100, 100, 100, NULL);
    INSERT INTO auth_identities (id, user_id, provider, subject, status, generation,
      created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms)
      VALUES ('identity-1', 'user-1', 'local', 'alice', 'active', 1, 100, 100, 100, NULL);
    INSERT INTO teams (id, name, created_at_ms) VALUES ('team-1', 'Team', 100);
    INSERT INTO team_memberships (team_id, user_id, role, status, version, created_at_ms, revoked_at_ms)
      VALUES ('team-1', 'user-1', 'owner', 'active', 1, 100, NULL);
    INSERT INTO credential_handles (
      id, provider, broker_kind, usage, broker_receipt_digest, authority_binding_digest,
      team_id, user_id, external_tenant_id, external_app_id,
      identity_installation_id, identity_installation_revision, external_subject,
      provider_proof_replay_digest, status, generation, replaces_handle_id, replaces_generation,
      created_by_user_id, created_by_user_generation, created_by_auth_identity_id,
      created_by_auth_identity_generation, updated_by_user_id, updated_by_user_generation,
      updated_by_auth_identity_id, updated_by_auth_identity_generation,
      created_at_ms, updated_at_ms, revoked_at_ms
    ) VALUES (
      'txch_v1_${"1".repeat(64)}', 'telegram', 'oauth-envelope', 'installation',
      '${"a".repeat(64)}', '${"b".repeat(64)}', 'team-1', NULL, '998877', '998877',
      NULL, NULL, NULL, NULL, 'active', 1, NULL, NULL,
      'user-1', 1, 'identity-1', 1, 'user-1', 1, 'identity-1', 1, 100, 100, NULL
    );
    INSERT INTO channel_installations (
      id, team_id, provider, external_tenant_id, external_app_id,
      credential_handle_id, credential_handle_generation,
      reviewed_scopes_schema, reviewed_scopes_json, reviewed_scopes_digest,
      capabilities_schema, capabilities_json, capabilities_digest,
      status, revision, created_by_user_id, created_under_membership_version,
      created_by_user_generation, created_by_auth_identity_id, created_by_auth_identity_generation,
      updated_by_user_id, updated_under_membership_version, updated_by_user_generation,
      updated_by_auth_identity_id, updated_by_auth_identity_generation,
      created_at_ms, updated_at_ms, revoked_at_ms
    ) VALUES (
      'inst-1', 'team-1', 'telegram', '998877', '998877',
      'txch_v1_${"1".repeat(64)}', 1,
      1, '["bot:send-message"]', '${sha256Json('["bot:send-message"]')}',
      1, '["bot:send-message"]', '${sha256Json('["bot:send-message"]')}',
      'active', 1, 'user-1', 1, 1, 'identity-1', 1, 'user-1', 1, 1, 'identity-1', 1, 100, 100, NULL
    );
  `);
}

function seedSecondInstallation(db: Database.Database): void {
  db.exec(`
    INSERT INTO credential_handles (
      id, provider, broker_kind, usage, broker_receipt_digest, authority_binding_digest,
      team_id, user_id, external_tenant_id, external_app_id,
      identity_installation_id, identity_installation_revision, external_subject,
      provider_proof_replay_digest, status, generation, replaces_handle_id, replaces_generation,
      created_by_user_id, created_by_user_generation, created_by_auth_identity_id,
      created_by_auth_identity_generation, updated_by_user_id, updated_by_user_generation,
      updated_by_auth_identity_id, updated_by_auth_identity_generation,
      created_at_ms, updated_at_ms, revoked_at_ms
    ) VALUES (
      'txch_v1_${"2".repeat(64)}', 'telegram', 'oauth-envelope', 'installation',
      '${"c".repeat(64)}', '${"d".repeat(64)}', 'team-1', NULL, '111111', '111111',
      NULL, NULL, NULL, NULL, 'active', 1, NULL, NULL,
      'user-1', 1, 'identity-1', 1, 'user-1', 1, 'identity-1', 1, 100, 100, NULL
    );
    INSERT INTO channel_installations (
      id, team_id, provider, external_tenant_id, external_app_id,
      credential_handle_id, credential_handle_generation,
      reviewed_scopes_schema, reviewed_scopes_json, reviewed_scopes_digest,
      capabilities_schema, capabilities_json, capabilities_digest,
      status, revision, created_by_user_id, created_under_membership_version,
      created_by_user_generation, created_by_auth_identity_id, created_by_auth_identity_generation,
      updated_by_user_id, updated_under_membership_version, updated_by_user_generation,
      updated_by_auth_identity_id, updated_by_auth_identity_generation,
      created_at_ms, updated_at_ms, revoked_at_ms
    ) VALUES (
      'inst-2', 'team-1', 'telegram', '111111', '111111',
      'txch_v1_${"2".repeat(64)}', 1,
      1, '["bot:send-message"]', '${sha256Json('["bot:send-message"]')}',
      1, '["bot:send-message"]', '${sha256Json('["bot:send-message"]')}',
      'active', 1, 'user-1', 1, 1, 'identity-1', 1, 'user-1', 1, 1, 'identity-1', 1, 100, 100, NULL
    );
  `);
}

function sha256Json(json: string): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require("node:crypto").createHash("sha256").update(json, "utf8").digest("hex");
}
