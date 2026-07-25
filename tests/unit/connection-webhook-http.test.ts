import type Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { handleSlackWebhook, handleTelegramWebhook } from "@/lib/connections/webhook-http";
import { createWebhookAuthStore } from "@/lib/connections/webhook-auth";
import type { InboundKernelCommand } from "@/lib/connections/ingest";
import type { ConnectionAuthority } from "@/lib/connections/authority";
import type { InboundAttributionResolution } from "@/lib/connections/contracts";

const SECRET_TOKEN = "0011223344556677";
const SECRET_DIGEST = createHash("sha256").update(SECRET_TOKEN, "utf8").digest("hex");

describe("connection webhook ingress", () => {
  let database: TeamSessionDatabase | undefined;
  afterEach(() => {
    database?.close();
    database = undefined;
  });

  function setupDb(options: { binding?: boolean; provider?: "telegram" | "slack" } = {}) {
    const db = openTeamSessionDatabase({ filename: ":memory:" });
    database = db;
    const provider = options.provider ?? "telegram";
    const tenant = provider === "telegram" ? "998877" : "T1";
    seed(db.db, provider, tenant, options.binding ?? true);
    if (provider === "telegram") {
      createWebhookAuthStore(db.db).recordWebhookAuthDigest({
        installationId: "inst-1",
        provider: "telegram",
        authDigest: SECRET_DIGEST,
        createdAtMs: 100,
      });
    }
    return db;
  }

  function attributionResolution(): InboundAttributionResolution {
    return Object.freeze({
      direction: "inbound",
      action: "comment",
      provider: "telegram",
      session: Object.freeze({
        id: "session-1",
        teamId: "team-1",
        accessRevision: 1,
        steeringRevision: 1,
        controlRevision: 1,
        runtimeAuthorizationGeneration: 1,
      }),
      installation: Object.freeze({
        id: "inst-1",
        revision: 1,
        externalTenantId: "998877",
        externalAppId: "998877",
        credentialHandleId: "txch_v1_" + "1".repeat(64),
        credentialHandleGeneration: 1,
      }),
      binding: Object.freeze({
        id: "binding-1",
        revision: 1,
        conversationKind: "channel",
        externalConversationId: "777",
        externalThreadId: "",
        inboundPolicy: Object.freeze({ mode: "comments-only", requireLinkedIdentity: true }),
        inboundPolicyDigest: "d".repeat(64),
      }),
      identity: Object.freeze({
        connectionId: "conn-1",
        connectionGeneration: 1,
        userId: "user-1",
        externalSubject: "777",
        scopes: ["identity:telegram"],
        scopesDigest: "e".repeat(64),
        credentialHandleId: null,
        credentialHandleGeneration: null,
      }),
    });
  }

  function telegramDeps(db: TeamSessionDatabase, dispatched: InboundKernelCommand[]) {
    return {
      withConnectionDatabase: <T>(op: (d: Database.Database) => T): T => op(db.db),
      withConnectionAuthority: <T>(op: (authority: ConnectionAuthority) => T): T =>
        op({
          resolveInboundAttribution: () => attributionResolution(),
          completeLinkChallenge: vi.fn(() => ({ id: "conn-1" })),
        } as never),
      exchangeClient: null,
      dispatchKernelCommand: async (command: InboundKernelCommand) => {
        dispatched.push(command);
        return { accepted: true, replayed: false };
      },
    };
  }

  function telegramRequest(update: unknown, secretToken: string | null = SECRET_TOKEN): Request {
    return new Request("https://terminalx.example/api/connections/webhooks/telegram/inst-1", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(secretToken === null ? {} : { "x-telegram-bot-api-secret-token": secretToken }),
      },
      body: JSON.stringify(update),
    });
  }

  it("rejects a missing or wrong Telegram secret token with a uniform 401", async () => {
    const db = setupDb();
    const dispatched: InboundKernelCommand[] = [];
    const deps = telegramDeps(db, dispatched);
    expect((await handleTelegramWebhook(telegramRequest({}, null), "inst-1", deps)).status).toBe(
      401
    );
    expect((await handleTelegramWebhook(telegramRequest({}, "wrong"), "inst-1", deps)).status).toBe(
      401
    );
    // Unknown installation is indistinguishable from a bad secret.
    expect(
      (await handleTelegramWebhook(telegramRequest({}, SECRET_TOKEN), "inst-404", deps)).status
    ).toBe(401);
    expect(dispatched).toEqual([]);
  });

  it("ingests an authenticated Telegram conversation message as an attributed comment", async () => {
    const db = setupDb();
    const dispatched: InboundKernelCommand[] = [];
    const deps = telegramDeps(db, dispatched);
    const update = {
      update_id: 900,
      message: { from: { id: 777 }, chat: { id: 777 }, text: "run the tests" },
    };
    const res = await handleTelegramWebhook(telegramRequest(update), "inst-1", deps);
    expect(res.status).toBe(200);
    expect(dispatched[0]).toMatchObject({
      type: "comment.add",
      sessionId: "session-1",
      actorUserId: "user-1",
      body: "run the tests",
      idempotencyKey: "900",
    });
    // Replay of the same update_id is acknowledged without re-dispatching.
    const replay = await handleTelegramWebhook(telegramRequest(update), "inst-1", deps);
    expect(replay.status).toBe(200);
    expect(dispatched).toHaveLength(1);
  });

  it("routes a /start deep link into challenge completion, acknowledging failures", async () => {
    const db = setupDb();
    const completions: unknown[] = [];
    const deps = {
      ...telegramDeps(db, []),
      withConnectionAuthority: <T>(op: (authority: ConnectionAuthority) => T): T =>
        op({
          completeLinkChallenge: (input: unknown) => {
            completions.push(input);
            throw new Error("Link Challenge is invalid or already used");
          },
        } as never),
    };
    const res = await handleTelegramWebhook(
      telegramRequest({
        update_id: 901,
        message: { from: { id: 777 }, chat: { id: 777 }, text: "/start CHALLENGE" },
      }),
      "inst-1",
      deps
    );
    // Acknowledged-not-processed: a rejected linking attempt is still a 200.
    expect(res.status).toBe(200);
    expect(completions).toHaveLength(1);
  });

  it("acknowledges without processing when no binding routes the conversation", async () => {
    const db = setupDb({ binding: false });
    const dispatched: InboundKernelCommand[] = [];
    const deps = telegramDeps(db, dispatched);
    const res = await handleTelegramWebhook(
      telegramRequest({
        update_id: 902,
        message: { from: { id: 777 }, chat: { id: 777 }, text: "hello" },
      }),
      "inst-1",
      deps
    );
    expect(res.status).toBe(200);
    expect(dispatched).toEqual([]);
  });

  it("fails closed on oversized and malformed Telegram bodies", async () => {
    const db = setupDb();
    const deps = { ...telegramDeps(db, []), maxBodyBytes: 64 };
    const oversized = await handleTelegramWebhook(
      telegramRequest({ update_id: 1, message: { text: "x".repeat(200) } }),
      "inst-1",
      deps
    );
    expect(oversized.status).toBe(413);
    const malformed = await handleTelegramWebhook(
      new Request("https://terminalx.example/api/connections/webhooks/telegram/inst-1", {
        method: "POST",
        headers: { "x-telegram-bot-api-secret-token": SECRET_TOKEN },
        body: "not-json",
      }),
      "inst-1",
      telegramDeps(db, [])
    );
    expect(malformed.status).toBe(400);
  });

  function slackDeps(
    db: TeamSessionDatabase,
    dispatched: InboundKernelCommand[],
    verify: (input: { signature: string }) => { valid: boolean; withinReplayWindow: boolean }
  ) {
    return {
      withConnectionDatabase: <T>(op: (d: Database.Database) => T): T => op(db.db),
      withConnectionAuthority: <T>(op: (authority: ConnectionAuthority) => T): T =>
        op({
          resolveInboundAttribution: () => ({
            ...attributionResolution(),
            provider: "slack",
          }),
        } as never),
      exchangeClient: {
        verifySlackWebhook: async (input: { signature: string }) => verify(input),
        slackOauth: async () => {
          throw new Error("unused");
        },
        telegramBotToken: async () => {
          throw new Error("unused");
        },
      },
      dispatchKernelCommand: async (command: InboundKernelCommand) => {
        dispatched.push(command);
        return { accepted: true, replayed: false };
      },
    };
  }

  function slackRequest(envelope: unknown, signature = "v0=good"): Request {
    return new Request("https://terminalx.example/api/connections/webhooks/slack", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-slack-request-timestamp": "1700000000",
        "x-slack-signature": signature,
      },
      body: JSON.stringify(envelope),
    });
  }

  it("rejects a Slack event whose signature does not verify", async () => {
    const db = setupDb({ provider: "slack" });
    const dispatched: InboundKernelCommand[] = [];
    const deps = slackDeps(db, dispatched, () => ({ valid: false, withinReplayWindow: true }));
    const res = await handleSlackWebhook(
      slackRequest({
        type: "event_callback",
        team_id: "T1",
        event_id: "Ev1",
        event: { type: "message", user: "U1", channel: "777", text: "hi" },
      }),
      deps
    );
    expect(res.status).toBe(401);
    expect(dispatched).toEqual([]);
  });

  it("rejects a stale-timestamp Slack event (outside the replay window)", async () => {
    const db = setupDb({ provider: "slack" });
    const deps = slackDeps(db, [], () => ({ valid: true, withinReplayWindow: false }));
    const res = await handleSlackWebhook(
      slackRequest({
        type: "event_callback",
        team_id: "T1",
        event_id: "Ev1",
        event: { type: "message", user: "U1", channel: "777", text: "hi" },
      }),
      deps
    );
    expect(res.status).toBe(401);
  });

  it("ingests a verified Slack message and echoes url_verification only when signed", async () => {
    const db = setupDb({ provider: "slack" });
    const dispatched: InboundKernelCommand[] = [];
    const deps = slackDeps(db, dispatched, (input) => ({
      valid: input.signature === "v0=good",
      withinReplayWindow: true,
    }));
    const res = await handleSlackWebhook(
      slackRequest({
        type: "event_callback",
        team_id: "T1",
        event_id: "Ev2",
        event: { type: "message", user: "U1", channel: "777", text: "deploy it" },
      }),
      deps
    );
    expect(res.status).toBe(200);
    expect(dispatched[0]).toMatchObject({ type: "comment.add", body: "deploy it" });

    const verification = await handleSlackWebhook(
      slackRequest({ type: "url_verification", challenge: "abc" }),
      deps
    );
    expect(verification.status).toBe(200);
    expect(await verification.json()).toEqual({ challenge: "abc" });

    const forgedVerification = await handleSlackWebhook(
      slackRequest({ type: "url_verification", challenge: "abc" }, "v0=forged"),
      deps
    );
    expect(forgedVerification.status).toBe(401);
  });

  it("rejects an unknown Slack tenant with 401 before verification", async () => {
    const db = setupDb({ provider: "slack" });
    const verify = vi.fn(() => ({ valid: true, withinReplayWindow: true }));
    const deps = slackDeps(db, [], verify);
    const res = await handleSlackWebhook(
      slackRequest({
        type: "event_callback",
        team_id: "T-UNKNOWN",
        event_id: "Ev3",
        event: { type: "message", user: "U1", channel: "777", text: "hi" },
      }),
      deps
    );
    expect(res.status).toBe(401);
    expect(verify).not.toHaveBeenCalled();
  });
});

function seed(
  db: Database.Database,
  provider: "telegram" | "slack",
  tenant: string,
  withBinding: boolean
): void {
  const scopesJson = '["bot:send-message"]';
  const scopesDigest = createHash("sha256").update(scopesJson, "utf8").digest("hex");
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
    INSERT INTO projects (id, team_id, name, source_ref, created_at_ms)
      VALUES ('project-1', 'team-1', 'Project', NULL, 100);
    INSERT INTO sessions (
      id, team_id, project_id, name, status, steering_policy,
      access_revision, assignee_revision, supervision_revision, steering_revision,
      control_revision, control_epoch, runtime_authorization_generation,
      runtime_authorization_state, run_state_revision, next_sequence,
      runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms
    ) VALUES (
      'session-1', 'team-1', 'project-1', 'Session', 'active', 'shared',
      1, 1, 1, 1, 1, 1, 1, 'enforced', 1, 1,
      'local-tmux', 'trusted-shared-host', 'tmux-wh', 0, 100
    );
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
      'txch_v1_${"1".repeat(64)}', '${provider}', 'oauth-envelope', 'installation',
      '${"a".repeat(64)}', '${"b".repeat(64)}', 'team-1', NULL, '${tenant}', '${
        provider === "telegram" ? tenant : "A1"
      }',
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
      'inst-1', 'team-1', '${provider}', '${tenant}', '${provider === "telegram" ? tenant : "A1"}',
      'txch_v1_${"1".repeat(64)}', 1,
      1, '${scopesJson}', '${scopesDigest}',
      1, '${scopesJson}', '${scopesDigest}',
      'active', 1, 'user-1', 1, 1, 'identity-1', 1, 'user-1', 1, 1, 'identity-1', 1, 100, 100, NULL
    );
  `);
  if (withBinding) {
    const inbound = JSON.stringify({ mode: "comments-only", requireLinkedIdentity: true });
    const outbound = JSON.stringify({ mode: "disabled", allowArtifacts: false });
    const inboundDigest = createHash("sha256").update(inbound, "utf8").digest("hex");
    const outboundDigest = createHash("sha256").update(outbound, "utf8").digest("hex");
    db.exec(`
      INSERT INTO channel_bindings (
        id, session_id, team_id, installation_id, installation_revision,
        provider, conversation_kind, external_conversation_id, external_thread_id,
        policy_schema, inbound_policy_json, inbound_policy_digest,
        outbound_policy_json, outbound_policy_digest,
        status, revision, created_by_user_id, created_under_membership_version,
        created_by_user_generation, created_by_auth_identity_id,
        created_by_auth_identity_generation,
        updated_by_user_id, updated_under_membership_version,
        updated_by_user_generation, updated_by_auth_identity_id,
        updated_by_auth_identity_generation,
        created_at_ms, updated_at_ms, revoked_at_ms
      ) VALUES (
        'binding-1', 'session-1', 'team-1', 'inst-1', 1,
        '${provider}', 'channel', '777', '',
        1, '${inbound}', '${inboundDigest}', '${outbound}', '${outboundDigest}',
        'active', 1, 'user-1', 1, 1, 'identity-1', 1, 'user-1', 1, 1, 'identity-1', 1,
        100, 100, NULL
      );
    `);
  }
}
