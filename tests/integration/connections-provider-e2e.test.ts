import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { createSecretBrokerClient } from "@/lib/connections/secret-broker-client";
import { createCredentialProxyClient } from "@/lib/connections/credential-proxy-client";
import { createProviderExchangeClient } from "@/lib/connections/provider-exchange-client";
import { secretBrokerExpectationDigest } from "@/lib/connections/secret-broker-shared";
import {
  createBrokerReceiptVerifier,
  readBrokerVerificationKey,
} from "@/lib/connections/secret-broker-verifier";
import {
  createConnectionAuthority,
  type CredentialHandleRegistrationExpectation,
} from "@/lib/connections/authority";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { createWebhookDeliveryDedup } from "@/lib/connections/webhook-dedup";
import { ingestInboundMessage, type InboundKernelCommand } from "@/lib/connections/ingest";
import { deliverOutboundMessage } from "@/lib/connections/outbound-worker";
import {
  normalizeTelegramUpdate,
  verifyTelegramDeepLinkProof,
  verifyTelegramWebhookSecretToken,
} from "@/lib/connections/providers/telegram-adapter";
import {
  TELEGRAM_IDENTITY_LINK_SCOPES,
  TELEGRAM_INSTALLATION_REVIEWED_SCOPES,
  TELEGRAM_INSTALLATION_CAPABILITIES,
} from "@/lib/connections/providers/scopes";

const REPO_ROOT = path.resolve(__dirname, "../..");
const DAEMON = path.join(REPO_ROOT, "packages/secret-broker/src/daemon.ts");
const HELPER_SOURCE = path.join(
  REPO_ROOT,
  "packages/secret-broker/native/terminalx-secret-broker-peercred.c"
);
const TSX = path.join(REPO_ROOT, "node_modules/.bin/tsx");
const BOT_TOKEN = "998877:AA-Very-Secret-Bot-Token";
const BOT_ID = "998877";

const temporaryDirectories: string[] = [];
const children: ChildProcess[] = [];
const servers: http.Server[] = [];
const databases: TeamSessionDatabase[] = [];

function supported(): boolean {
  return (
    process.platform === "linux" &&
    fs.existsSync(TSX) &&
    spawnSync("sh", ["-c", "command -v cc"]).status === 0
  );
}

function temporaryRoot(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "connections-e2e-"));
  fs.chmodSync(dir, 0o700);
  temporaryDirectories.push(dir);
  return dir;
}

interface FakeProvider {
  readonly origin: string;
  readonly requests: { method: string; url: string; body: string }[];
}

async function startFakeTelegram(): Promise<FakeProvider> {
  const requests: FakeProvider["requests"] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const url = req.url ?? "";
      requests.push({
        method: req.method ?? "",
        url,
        body: Buffer.concat(chunks).toString("utf8"),
      });
      res.writeHead(200, { "content-type": "application/json" });
      if (url.endsWith("/getMe")) {
        res.end(JSON.stringify({ ok: true, result: { id: 998877, username: "example_bot" } }));
      } else if (url.endsWith("/setWebhook")) {
        res.end(JSON.stringify({ ok: true, result: true }));
      } else if (url.endsWith("/sendMessage")) {
        res.end(JSON.stringify({ ok: true, result: { message_id: 4242, date: 1700 } }));
      } else {
        res.end(JSON.stringify({ ok: false }));
      }
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no address");
  return { origin: `http://127.0.0.1:${address.port}`, requests };
}

async function startFakeSlack(): Promise<FakeProvider> {
  const requests: FakeProvider["requests"] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const url = req.url ?? "";
      requests.push({
        method: req.method ?? "",
        url,
        body: Buffer.concat(chunks).toString("utf8"),
      });
      res.writeHead(200, { "content-type": "application/json" });
      if (url.endsWith("/api/oauth.v2.access")) {
        res.end(
          JSON.stringify({
            ok: true,
            access_token: "xoxb-slack-secret-bot-token",
            team: { id: "T1" },
            app_id: "A1",
            bot_user_id: "UBOT",
            scope: "chat:write,channels:read",
          })
        );
      } else {
        res.end(JSON.stringify({ ok: false }));
      }
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no address");
  return { origin: `http://127.0.0.1:${address.port}`, requests };
}

function writeBootstrap(rootDir: string, telegramOrigin: string, slackOrigin: string): string {
  const helper = path.join(rootDir, "peercred");
  const compile = spawnSync("cc", [
    "-std=c17",
    "-O2",
    "-Wall",
    "-Werror",
    HELPER_SOURCE,
    "-o",
    helper,
  ]);
  if (compile.status !== 0) throw new Error("compile failed");
  fs.chmodSync(helper, 0o700);
  const executableSha256 = createHash("sha256").update(fs.readFileSync(helper)).digest("hex");
  const configPath = path.join(rootDir, "bootstrap.json");
  fs.writeFileSync(
    configPath,
    JSON.stringify({
      rootDir,
      expectedOwnerUid: typeof process.geteuid === "function" ? process.geteuid() : 0,
      expectedParentPid: null,
      peercred: { executableFile: helper, executableSha256 },
      adapters: { oauthEnvelope: true },
      receiptTtlMs: 60_000,
      reconcileIntervalMs: 1000,
      proxy: {
        enabled: true,
        originOverrides: { "api.telegram.org": telegramOrigin },
        requestTimeoutMs: 5000,
      },
      exchange: {
        enabled: true,
        originOverrides: { "api.telegram.org": telegramOrigin, "slack.com": slackOrigin },
        requestTimeoutMs: 5000,
      },
    })
  );
  fs.chmodSync(configPath, 0o600);
  return configPath;
}

async function startDaemon(configPath: string): Promise<ChildProcess> {
  const child = spawn(TSX, [DAEMON, configPath], {
    cwd: REPO_ROOT,
    stdio: ["ignore", "ignore", "pipe"],
  });
  children.push(child);
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("daemon did not become ready")), 30_000);
    let buffer = "";
    child.stderr?.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      if (buffer.includes('"event":"broker.ready"')) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`daemon exited early with code ${code}: ${buffer}`));
    });
  });
  return child;
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    child.once("exit", () => resolve());
    child.kill("SIGKILL");
  });
}

afterEach(async () => {
  while (children.length > 0) await stop(children.pop()!);
  while (servers.length > 0) {
    const server = servers.pop()!;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  while (databases.length > 0) databases.pop()!.close();
  while (temporaryDirectories.length > 0) {
    fs.rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

function seedAuthority(db: Database.Database): void {
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
      'local-tmux', 'trusted-shared-host', 'tmux-e2e', 0, 100
    );
  `);
}

function freshActor() {
  const now = Date.now();
  return Object.freeze({
    userId: "user-1",
    userGeneration: 1,
    authProvider: "local" as const,
    authSubject: "alice",
    authIdentityGeneration: 1,
    authenticatedAtMs: now,
    credentialIssuedAtMs: now,
    credentialExpiresAtMs: now + 86_400_000,
    credentialJtiDigest: "a".repeat(64),
    device: { provenance: "browser" as const },
  });
}

describe("connections provider end-to-end over the real broker child process", () => {
  it("installs, links, binds, ingests inbound, and delivers outbound without leaking the token", async () => {
    if (!supported()) return;
    const rootDir = temporaryRoot();
    const telegram = await startFakeTelegram();
    const slack = await startFakeSlack();
    await startDaemon(writeBootstrap(rootDir, telegram.origin, slack.origin));

    const brokerClient = createSecretBrokerClient({
      socketPath: path.join(rootDir, "broker.sock"),
    });
    const exchangeClient = createProviderExchangeClient({
      socketPath: path.join(rootDir, "broker.sock"),
    });
    const proxyClient = createCredentialProxyClient({
      socketPath: path.join(rootDir, "proxy.sock"),
    });
    const theActor = freshActor();

    // The installation expectation the authority will bind the receipt to.
    const installationExpectation: CredentialHandleRegistrationExpectation = Object.freeze({
      provider: "telegram",
      brokerKind: "oauth-envelope",
      usage: "installation",
      authorityBinding: Object.freeze({
        kind: "installation",
        teamId: "team-1",
        externalTenantId: BOT_ID,
        externalAppId: BOT_ID,
      }),
      replaces: null,
    });
    const expectationDigest = secretBrokerExpectationDigest(installationExpectation);

    // 1) Acquire the Telegram bot credential inside the broker (getMe + setWebhook
    // hit the fake provider). Only a receipt + identity + secret-token digest come back.
    const acquired = await exchangeClient.telegramBotToken({
      botToken: BOT_TOKEN,
      expectedTenantId: BOT_ID,
      expectedAppId: BOT_ID,
      webhookUrl: "https://terminalx.example/api/connections/webhooks/telegram",
      expectationDigest,
    });
    expect(JSON.stringify(acquired)).not.toContain(BOT_TOKEN);
    expect(acquired.botIdentity).toMatchObject({ provider: "telegram", botId: BOT_ID });
    expect(acquired.webhookAuthDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(telegram.requests.some((r) => r.url.endsWith("/getMe"))).toBe(true);
    expect(telegram.requests.some((r) => r.url.endsWith("/setWebhook"))).toBe(true);

    // 2) Admit the credential handle into the authority using the real signed
    // receipt verified against the broker's published key, then finalize the broker.
    const verificationKey = readBrokerVerificationKey(rootDir);
    if (!verificationKey) throw new Error("verification key unavailable");
    const receiptVerifier = createBrokerReceiptVerifier({ verificationPublicKey: verificationKey });

    const database = openTeamSessionDatabase({ filename: ":memory:" });
    databases.push(database);
    seedAuthority(database.db);
    const authority = createConnectionAuthority({
      db: database.db,
      verifyCredentialHandleRegistration: receiptVerifier,
      verifyProviderProof: verifyTelegramDeepLinkProof,
      validateAuthenticationSnapshot: () => true,
    });

    const installation = authority.createChannelInstallation({
      actor: theActor,
      teamId: "team-1",
      provider: "telegram",
      externalTenantId: BOT_ID,
      externalAppId: BOT_ID,
      expectedBrokerKind: "oauth-envelope",
      credentialBrokerProof: acquired.receipt,
      reviewedScopes: TELEGRAM_INSTALLATION_REVIEWED_SCOPES,
      capabilities: TELEGRAM_INSTALLATION_CAPABILITIES,
    });
    await brokerClient.finalizeRegistration(
      acquired.receipt.payload.handleId,
      acquired.receipt.payload.receiptId
    );
    expect((await brokerClient.handleStatus(acquired.receipt.payload.handleId)).status).toBe(
      "active"
    );

    // 3) Link a Telegram identity via a verified /start deep link on an
    // authenticated webhook, then bind the conversation to the Session.
    const issued = authority.issueLinkChallenge({
      actor: theActor,
      installationId: installation.id,
      expectedInstallationRevision: installation.revision,
      requestedScopes: TELEGRAM_IDENTITY_LINK_SCOPES,
    });
    // The webhook secret-token header verifies by digest (no broker roundtrip).
    // (We do not hold the raw token; assert the digest gate works both ways.)
    expect(verifyTelegramWebhookSecretToken("wrong", acquired.webhookAuthDigest)).toBe(false);
    const startUpdate = {
      update_id: 500,
      message: { from: { id: 777 }, chat: { id: 777 }, text: `/start ${issued.challenge}` },
    };
    const startNorm = normalizeTelegramUpdate(startUpdate, {
      externalTenantId: BOT_ID,
      externalAppId: BOT_ID,
    });
    expect(startNorm.deepLink).not.toBeNull();
    const connection = authority.completeLinkChallenge({
      challenge: issued.challenge,
      providerProof: startNorm.deepLink,
    });
    expect(connection).toMatchObject({ userId: "user-1", externalSubject: "777" });

    const binding = authority.createChannelBinding({
      actor: theActor,
      sessionId: "session-1",
      installationId: installation.id,
      expectedInstallationRevision: installation.revision,
      conversationKind: "channel",
      externalConversationId: "777",
      inboundPolicy: { mode: "comments-only", requireLinkedIdentity: true },
      outboundPolicy: { mode: "all-session-messages", allowArtifacts: false },
    });

    // 4) Inbound: a linked conversation message becomes an attributed comment.
    const dedup = createWebhookDeliveryDedup(database.db);
    const dispatched: InboundKernelCommand[] = [];
    const inboundMessageUpdate = {
      update_id: 501,
      message: { from: { id: 777 }, chat: { id: 777 }, text: "please rerun the build" },
    };
    const inboundNorm = normalizeTelegramUpdate(inboundMessageUpdate, {
      externalTenantId: BOT_ID,
      externalAppId: BOT_ID,
    });
    expect(inboundNorm.message).not.toBeNull();
    const outcome = await ingestInboundMessage(
      {
        dedup,
        resolveInboundAttribution: (i) => authority.resolveInboundAttribution(i),
        bindingInboundPolicy: () => ({ mode: "comments-only", requireLinkedIdentity: true }),
        dispatch: async (command) => {
          dispatched.push(command);
          return { accepted: true, replayed: false };
        },
      },
      {
        message: inboundNorm.message!,
        bindingId: binding.id,
        expectedBindingRevision: binding.revision,
        expectedInstallationRevision: installation.revision,
        installationId: installation.id,
        action: "comment",
      }
    );
    expect(outcome).toEqual({ kind: "processed", action: "comment", replayed: false });
    expect(dispatched[0]).toMatchObject({
      type: "comment.add",
      sessionId: "session-1",
      body: "please rerun the build",
      actorUserId: "user-1",
      idempotencyScope: `telegram:${BOT_ID}`,
      idempotencyKey: "501",
    });
    // Replayed inbound is deduped.
    const replay = await ingestInboundMessage(
      {
        dedup,
        resolveInboundAttribution: (i) => authority.resolveInboundAttribution(i),
        bindingInboundPolicy: () => ({ mode: "comments-only", requireLinkedIdentity: true }),
        dispatch: async () => {
          throw new Error("must not re-dispatch a replay");
        },
      },
      {
        message: inboundNorm.message!,
        bindingId: binding.id,
        expectedBindingRevision: binding.revision,
        expectedInstallationRevision: installation.revision,
        installationId: installation.id,
        action: "comment",
      }
    );
    expect(replay).toEqual({ kind: "dropped-replay" });

    // 5) Outbound: a session message is delivered through the proxy to Telegram.
    const decision = await deliverOutboundMessage(
      {
        proxyClient,
        resolveOutboundBinding: (i) => authority.resolveOutboundBinding(i),
      },
      {
        bindingId: binding.id,
        expectedBindingRevision: binding.revision,
        expectedInstallationRevision: installation.revision,
        messageKind: "session-message",
        includesArtifacts: false,
        text: "the build passed",
        attempt: 0,
      }
    );
    expect(decision).toMatchObject({ delivered: true, reason: "delivered" });

    const sendRequest = telegram.requests.find((r) => r.url.endsWith("/sendMessage"));
    expect(sendRequest).toBeDefined();
    // The bot token reached the provider at the effect boundary...
    expect(sendRequest!.url).toBe(`/bot${BOT_TOKEN}/sendMessage`);
    expect(JSON.parse(sendRequest!.body)).toEqual({ chat_id: "777", text: "the build passed" });
    // ...but never appears in the proxy result returned over the socket.
    expect(JSON.stringify(decision)).not.toContain(BOT_TOKEN);
    expect(JSON.stringify(decision)).not.toContain("/bot");
  }, 60_000);

  it("acquires a Slack installation and verifies webhooks inside the broker", async () => {
    if (!supported()) return;
    const rootDir = temporaryRoot();
    const telegram = await startFakeTelegram();
    const slack = await startFakeSlack();
    await startDaemon(writeBootstrap(rootDir, telegram.origin, slack.origin));

    const exchangeClient = createProviderExchangeClient({
      socketPath: path.join(rootDir, "broker.sock"),
    });
    const expectationDigest = secretBrokerExpectationDigest({
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "installation",
      authorityBinding: {
        kind: "installation",
        teamId: "team-1",
        externalTenantId: "T1",
        externalAppId: "A1",
      },
      replaces: null,
    });

    const acquired = await exchangeClient.slackOauth({
      code: "oauth-code-abc",
      expectedTenantId: "T1",
      expectedAppId: "A1",
      expectationDigest,
      signingSecret: "slack-signing-secret-value",
    });
    expect(JSON.stringify(acquired)).not.toContain("xoxb-slack-secret-bot-token");
    expect(JSON.stringify(acquired)).not.toContain("slack-signing-secret-value");
    expect(acquired.installation).toMatchObject({
      provider: "slack",
      externalTenantId: "T1",
      externalAppId: "A1",
      externalBotUserId: "UBOT",
      grantedScopes: ["chat:write", "channels:read"],
    });

    // The broker computes the v0 HMAC with the stored signing secret.
    const timestamp = Math.floor(Date.now() / 1000);
    const body = '{"type":"event_callback"}';
    const { createHmac } = await import("node:crypto");
    const signature = `v0=${createHmac("sha256", "slack-signing-secret-value")
      .update(`v0:${timestamp}:${body}`, "utf8")
      .digest("hex")}`;
    expect(
      await exchangeClient.verifySlackWebhook({ expectationDigest, timestamp, body, signature })
    ).toEqual({ valid: true, withinReplayWindow: true });
    expect(
      await exchangeClient.verifySlackWebhook({
        expectationDigest,
        timestamp,
        body,
        signature: "v0=deadbeef",
      })
    ).toMatchObject({ valid: false });
  }, 60_000);

  it("drives install, rotation, and webhook ingress through the real HTTP route handlers", async () => {
    if (!supported()) return;
    const { handleCreateInstallation, handleRotateInstallation } =
      await import("@/lib/connections/installation-http");
    const { handleTelegramWebhook } = await import("@/lib/connections/webhook-http");
    const { handleIssueLinkChallenge } = await import("@/lib/connections/http");
    const { createWebhookAuthStore } = await import("@/lib/connections/webhook-auth");

    const rootDir = temporaryRoot();
    const telegram = await startFakeTelegram();
    const slack = await startFakeSlack();
    await startDaemon(writeBootstrap(rootDir, telegram.origin, slack.origin));

    const brokerClient = createSecretBrokerClient({
      socketPath: path.join(rootDir, "broker.sock"),
    });
    const exchangeClient = createProviderExchangeClient({
      socketPath: path.join(rootDir, "broker.sock"),
    });
    const verificationKey = readBrokerVerificationKey(rootDir);
    if (!verificationKey) throw new Error("verification key unavailable");

    const database = openTeamSessionDatabase({ filename: ":memory:" });
    databases.push(database);
    seedAuthority(database.db);
    const authority = createConnectionAuthority({
      db: database.db,
      verifyCredentialHandleRegistration: createBrokerReceiptVerifier({
        verificationPublicKey: verificationKey,
      }),
      verifyProviderProof: verifyTelegramDeepLinkProof,
      validateAuthenticationSnapshot: () => true,
    });

    const actorNow = Date.now();
    const requestActor = {
      kind: "human" as const,
      userId: "user-1",
      username: "alice",
      displayName: "Alice",
      legacyRole: "admin",
      authentication: {
        provider: "local" as const,
        subject: "alice",
        userGeneration: 1,
        identityGeneration: 1,
        authenticatedAtMs: actorNow,
        credentialIssuedAtMs: actorNow,
        credentialExpiresAtMs: actorNow + 86_400_000,
        credentialJtiDigest: "a".repeat(64),
        device: { provenance: "browser" as const },
      },
    };
    const withConnectionDatabase = <T>(op: (db: Database.Database) => T): T => op(database.db);
    const withConnectionAuthority = <T>(op: (a: typeof authority) => T): T => op(authority);
    const installDeps = {
      resolveActor: async () => requestActor,
      withConnectionAuthority,
      withConnectionDatabase,
      exchangeClient,
      brokerClient,
      rateLimitState: new Map<string, number[]>(),
    };

    // 1) Create the installation through the real POST route handler.
    const createResponse = await handleCreateInstallation(
      new Request("https://terminalx.example/api/connections/installations", {
        method: "POST",
        body: JSON.stringify({
          provider: "telegram",
          teamId: "team-1",
          botId: BOT_ID,
          botToken: BOT_TOKEN,
          webhookBaseUrl: "https://terminalx.example",
        }),
      }),
      installDeps
    );
    expect(createResponse.status).toBe(201);
    const createText = await createResponse.text();
    expect(createText).not.toContain(BOT_TOKEN);
    const created = JSON.parse(createText) as { installation: { id: string; revision: number } };
    const installationId = created.installation.id;

    // The broker set the webhook on the fake provider with an in-broker secret
    // token; recover the raw token exactly as Telegram would present it.
    const setWebhookBody = telegram.requests.find((r) => r.url.endsWith("/setWebhook"))!.body;
    const secretToken = new URLSearchParams(setWebhookBody).get("secret_token")!;
    expect(secretToken).toMatch(/^[0-9a-f]{64}$/);
    expect(
      withConnectionDatabase((db) =>
        createWebhookAuthStore(db).latestWebhookAuthDigest(installationId, "telegram")
      )
    ).toBe(createHash("sha256").update(secretToken, "utf8").digest("hex"));

    // 2) Issue a Link Challenge through the real route handler and complete it
    // by posting a /start deep link to the real webhook route handler.
    const challengeResponse = await handleIssueLinkChallenge(
      new Request("https://terminalx.example/api/connections/link-challenges", {
        method: "POST",
        body: JSON.stringify({
          installationId,
          expectedInstallationRevision: created.installation.revision,
          requestedScopes: TELEGRAM_IDENTITY_LINK_SCOPES,
        }),
      }),
      { resolveActor: async () => requestActor, withConnectionAuthority }
    );
    expect(challengeResponse.status).toBe(200);
    const { linkChallenge } = (await challengeResponse.json()) as {
      linkChallenge: { challenge: string };
    };

    const dispatched: InboundKernelCommand[] = [];
    const webhookDeps = {
      withConnectionAuthority,
      withConnectionDatabase,
      exchangeClient,
      dispatchKernelCommand: async (command: InboundKernelCommand) => {
        dispatched.push(command);
        return { accepted: true, replayed: false };
      },
    };
    const webhookRequest = (update: unknown, token = secretToken): Request =>
      new Request(`https://terminalx.example/api/connections/webhooks/telegram/${installationId}`, {
        method: "POST",
        headers: { "x-telegram-bot-api-secret-token": token },
        body: JSON.stringify(update),
      });

    // A forged secret token is a uniform 401.
    expect(
      (
        await handleTelegramWebhook(
          webhookRequest({ update_id: 1 }, "forged"),
          installationId,
          webhookDeps
        )
      ).status
    ).toBe(401);

    const linkResponse = await handleTelegramWebhook(
      webhookRequest({
        update_id: 600,
        message: {
          from: { id: 777 },
          chat: { id: 777 },
          text: `/start ${linkChallenge.challenge}`,
        },
      }),
      installationId,
      webhookDeps
    );
    expect(linkResponse.status).toBe(200);
    expect(
      database.db
        .prepare("SELECT user_id, external_subject, status FROM identity_connections")
        .get()
    ).toEqual({ user_id: "user-1", external_subject: "777", status: "active" });

    // 3) Bind the conversation and ingest a message through the webhook route.
    const binding = authority.createChannelBinding({
      actor: requestActor.authentication
        ? {
            userId: requestActor.userId,
            userGeneration: 1,
            authProvider: "local",
            authSubject: "alice",
            authIdentityGeneration: 1,
            authenticatedAtMs: actorNow,
            credentialIssuedAtMs: actorNow,
            credentialExpiresAtMs: actorNow + 86_400_000,
            credentialJtiDigest: "a".repeat(64),
            device: { provenance: "browser" },
          }
        : (undefined as never),
      sessionId: "session-1",
      installationId,
      expectedInstallationRevision: created.installation.revision,
      conversationKind: "channel",
      externalConversationId: "777",
      inboundPolicy: { mode: "comments-only", requireLinkedIdentity: true },
      outboundPolicy: { mode: "disabled", allowArtifacts: false },
    });
    expect(binding.status).toBe("active");
    const ingestResponse = await handleTelegramWebhook(
      webhookRequest({
        update_id: 601,
        message: { from: { id: 777 }, chat: { id: 777 }, text: "ship the release" },
      }),
      installationId,
      webhookDeps
    );
    expect(ingestResponse.status).toBe(200);
    expect(dispatched[0]).toMatchObject({
      type: "comment.add",
      sessionId: "session-1",
      actorUserId: "user-1",
      body: "ship the release",
      idempotencyKey: "601",
    });

    // 4) Rotate through the real rotation route: the old secret token stops
    // authenticating and the new one (set on the fake provider) takes over.
    const newBotToken = "998877:AA-Rotated-Bot-Token";
    const requestsBeforeRotate = telegram.requests.length;
    const rotateResponse = await handleRotateInstallation(
      new Request(
        `https://terminalx.example/api/connections/installations/${installationId}/rotate`,
        {
          method: "POST",
          body: JSON.stringify({
            provider: "telegram",
            botToken: newBotToken,
            webhookBaseUrl: "https://terminalx.example",
            expectedRevision: created.installation.revision,
            expectedHandleGeneration: 1,
          }),
        }
      ),
      installationId,
      installDeps
    );
    expect(rotateResponse.status).toBe(200);
    expect(await rotateResponse.text()).not.toContain(newBotToken);
    const rotatedSetWebhook = telegram.requests
      .slice(requestsBeforeRotate)
      .find((r) => r.url.endsWith("/setWebhook"))!;
    const rotatedSecretToken = new URLSearchParams(rotatedSetWebhook.body).get("secret_token")!;
    expect(rotatedSecretToken).not.toBe(secretToken);
    expect(
      (
        await handleTelegramWebhook(
          webhookRequest({ update_id: 700 }, secretToken),
          installationId,
          webhookDeps
        )
      ).status
    ).toBe(401);
    expect(
      (
        await handleTelegramWebhook(
          webhookRequest({ update_id: 700 }, rotatedSecretToken),
          installationId,
          webhookDeps
        )
      ).status
    ).toBe(200);
  }, 60_000);
});
