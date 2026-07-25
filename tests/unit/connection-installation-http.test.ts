import { describe, expect, it, vi } from "vitest";
import {
  createPendingSlackSecretStore,
  handleCreateInstallation,
  handleRotateInstallation,
  handleSlackOauthCallback,
  signInstallationState,
  verifyInstallationState,
  type InstallationHttpDependencies,
  type InstallStatePayload,
} from "@/lib/connections/installation-http";
import type { RequestActor } from "@/lib/request-actor";
import type { SecretBrokerReceipt } from "@/../packages/secret-broker/src/receipt-schema";

const STATE_SECRET = "state-secret-0123456789abcdef";
const BOT_TOKEN = "998877:AA-Rotation-Token-Value";

const canonicalActor: RequestActor = {
  kind: "human",
  userId: "user-1",
  username: "alice",
  displayName: "Alice",
  legacyRole: "admin",
  authentication: {
    provider: "local",
    subject: "alice",
    userGeneration: 1,
    identityGeneration: 1,
    authenticatedAtMs: 1_000,
    credentialIssuedAtMs: 1_000,
    credentialExpiresAtMs: 10_000,
    credentialJtiDigest: "a".repeat(64),
    device: { provenance: "browser" },
  },
};

function fakeReceipt(): SecretBrokerReceipt {
  return {
    payload: {
      schema: 1,
      kind: "terminalx.secret-broker-registration-receipt",
      brokerInstanceId: "b".repeat(32),
      brokerEpoch: 1,
      signingKeyId: "c".repeat(64),
      operationId: "op",
      handleId: "txch_v1_" + "0".repeat(64),
      receiptId: "rcp-1",
      provider: "telegram",
      brokerKind: "oauth-envelope",
      usage: "installation",
      expectationDigest: "d".repeat(64),
      hasReplacement: false,
      issuedAtMs: 1,
      expiresAtMs: 2,
    },
    signature: "s".repeat(86),
  } as unknown as SecretBrokerReceipt;
}

function adminMembershipDb() {
  return <T>(operation: (db: never) => T): T =>
    operation({
      prepare: () => ({
        get: () => ({ role: "owner" }),
        run: () => ({ changes: 1 }),
      }),
    } as never);
}

function post(body: unknown): Request {
  return new Request("https://terminalx.example/api/connections/installations", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("installation state signing", () => {
  const payload: InstallStatePayload = {
    v: 1,
    intent: "install",
    provider: "slack",
    teamId: "team-1",
    userId: "user-1",
    credentialJtiDigest: "a".repeat(64),
    externalTenantId: "T1",
    externalAppId: "A1",
    redirectUri: "https://terminalx.example/cb",
    nonce: "n1",
    expiresAtMs: 100_000,
  };

  it("round-trips a signed state and rejects tampering", () => {
    const state = signInstallationState(payload, STATE_SECRET);
    expect(verifyInstallationState(state, STATE_SECRET, 50_000)).toMatchObject({
      teamId: "team-1",
      nonce: "n1",
    });
    // Tampered payload byte.
    const tampered = state.slice(0, 12) + (state[12] === "A" ? "B" : "A") + state.slice(13);
    expect(verifyInstallationState(tampered, STATE_SECRET, 50_000)).toBeNull();
    // Wrong key.
    expect(verifyInstallationState(state, "other-secret-0123456789abcdef", 50_000)).toBeNull();
  });

  it("rejects an expired state", () => {
    const state = signInstallationState(payload, STATE_SECRET);
    expect(verifyInstallationState(state, STATE_SECRET, 100_000)).toBeNull();
  });

  it("pending secret store is single-use and TTL-bounded", () => {
    const store = createPendingSlackSecretStore();
    store.put("n1", "sig-secret", 10_000);
    expect(store.take("n1", 5_000)).toBe("sig-secret");
    expect(store.take("n1", 5_000)).toBeNull();
    store.put("n2", "sig-secret", 10_000);
    expect(store.take("n2", 10_000)).toBeNull();
  });
});

describe("telegram installation creation route", () => {
  function deps(
    overrides: Partial<InstallationHttpDependencies> = {}
  ): InstallationHttpDependencies {
    return {
      resolveActor: async () => canonicalActor,
      withConnectionDatabase: adminMembershipDb(),
      withConnectionAuthority: (op) =>
        op({
          createChannelInstallation: (input: { installationId?: string }) => ({
            id: input.installationId ?? "generated",
            revision: 1,
            status: "active",
          }),
        } as never),
      exchangeClient: {
        telegramBotToken: async () => ({
          receipt: fakeReceipt(),
          botIdentity: {
            provider: "telegram",
            externalTenantId: "998877",
            externalAppId: "998877",
            botId: "998877",
            username: "bot",
          },
          webhookAuthDigest: "e".repeat(64),
        }),
        slackOauth: async () => {
          throw new Error("unused");
        },
        verifySlackWebhook: async () => ({ valid: false, withinReplayWindow: false }),
      },
      brokerClient: null,
      clock: () => 1_000_000,
      idGenerator: () => "inst-fixed",
      rateLimitState: new Map(),
      ...overrides,
    };
  }

  const body = {
    provider: "telegram",
    teamId: "team-1",
    botId: "998877",
    botToken: BOT_TOKEN,
    webhookBaseUrl: "https://terminalx.example",
  };

  it("creates the installation with a pre-generated id and never echoes the token", async () => {
    const exchangeCalls: unknown[] = [];
    const d = deps({
      exchangeClient: {
        telegramBotToken: async (input) => {
          exchangeCalls.push(input);
          return {
            receipt: fakeReceipt(),
            botIdentity: {
              provider: "telegram",
              externalTenantId: "998877",
              externalAppId: "998877",
              botId: "998877",
              username: "bot",
            },
            webhookAuthDigest: "e".repeat(64),
          };
        },
        slackOauth: async () => {
          throw new Error("unused");
        },
        verifySlackWebhook: async () => ({ valid: false, withinReplayWindow: false }),
      },
    });
    const res = await handleCreateInstallation(post(body), d);
    expect(res.status).toBe(201);
    const text = await res.text();
    expect(text).not.toContain(BOT_TOKEN);
    expect(JSON.parse(text).installation.id).toBe("inst-fixed");
    // The webhook URL embeds the pre-generated installation id.
    expect(exchangeCalls[0]).toMatchObject({
      webhookUrl: "https://terminalx.example/api/connections/webhooks/telegram/inst-fixed",
    });
  });

  it("rejects a non-admin member before any exchange", async () => {
    const exchange = vi.fn();
    const d = deps({
      withConnectionDatabase: <T>(op: (db: never) => T): T =>
        op({ prepare: () => ({ get: () => ({ role: "member" }) }) } as never),
      exchangeClient: { telegramBotToken: exchange } as never,
    });
    const res = await handleCreateInstallation(post(body), d);
    expect(res.status).toBe(403);
    expect(exchange).not.toHaveBeenCalled();
  });

  it("requires an https webhook base and rejects an unauthenticated caller", async () => {
    const badBase = await handleCreateInstallation(
      post({ ...body, webhookBaseUrl: "http://terminalx.example" }),
      deps()
    );
    expect(badBase.status).toBe(400);
    const unauthenticated = await handleCreateInstallation(
      post(body),
      deps({ resolveActor: async () => null })
    );
    expect(unauthenticated.status).toBe(401);
  });

  it("rate limits repeated creation attempts per user", async () => {
    const state = new Map<string, number[]>();
    const d = deps({ rateLimitState: state });
    for (let index = 0; index < 5; index += 1) {
      const res = await handleCreateInstallation(post(body), d);
      expect(res.status).toBe(201);
    }
    const res = await handleCreateInstallation(post(body), d);
    expect(res.status).toBe(429);
  });

  it("aborts the pending broker registration when the authority rejects", async () => {
    const abortRegistration = vi.fn(async () => undefined);
    const d = deps({
      withConnectionAuthority: () => {
        throw new Error("Channel Installation credential rotation was fenced");
      },
      brokerClient: { abortRegistration } as never,
    });
    const res = await handleCreateInstallation(post(body), d);
    expect(res.status).toBe(409);
    expect(abortRegistration).toHaveBeenCalledWith("rcp-1");
  });
});

describe("slack install flow", () => {
  function slackDeps(
    pending = createPendingSlackSecretStore(),
    overrides: Partial<InstallationHttpDependencies> = {}
  ): InstallationHttpDependencies {
    return {
      resolveActor: async () => canonicalActor,
      withConnectionDatabase: adminMembershipDb(),
      withConnectionAuthority: (op) =>
        op({
          createChannelInstallation: () => ({ id: "inst-slack", revision: 1, status: "active" }),
        } as never),
      exchangeClient: {
        slackOauth: async () => ({
          receipt: fakeReceipt(),
          installation: {
            provider: "slack",
            externalTenantId: "T1",
            externalAppId: "A1",
            externalBotUserId: "U1",
            grantedScopes: ["chat:write", "channels:read"],
          },
        }),
        telegramBotToken: async () => {
          throw new Error("unused");
        },
        verifySlackWebhook: async () => ({ valid: false, withinReplayWindow: false }),
      },
      brokerClient: null,
      stateSecret: () => STATE_SECRET,
      pendingSlackSecrets: pending,
      clock: () => 1_000_000,
      nonceGenerator: () => "nonce-1",
      ...overrides,
    };
  }

  const startBody = {
    provider: "slack",
    teamId: "team-1",
    externalTenantId: "T1",
    externalAppId: "A1",
    signingSecret: "slack-signing-secret",
    redirectUri: "https://terminalx.example/api/connections/installations/slack/callback",
  };

  it("start returns a signed state and authorize URL without leaking the signing secret", async () => {
    const res = await handleCreateInstallation(post(startBody), slackDeps());
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain("slack-signing-secret");
    const json = JSON.parse(text) as { authorizeUrl: string; state: string };
    expect(json.authorizeUrl).toContain("https://slack.com/oauth/v2/authorize");
    expect(json.authorizeUrl).toContain("scope=chat%3Awrite%2Cchannels%3Aread");
    const payload = verifyInstallationState(json.state, STATE_SECRET, 1_000_001);
    expect(payload).toMatchObject({ intent: "install", teamId: "team-1", userId: "user-1" });
    expect(JSON.stringify(payload)).not.toContain("slack-signing-secret");
  });

  it("callback completes the installation for the initiating actor only", async () => {
    const pending = createPendingSlackSecretStore();
    const deps = slackDeps(pending);
    const startRes = await handleCreateInstallation(post(startBody), deps);
    const { state } = (await startRes.json()) as { state: string };

    // A different actor cannot complete the flow.
    const otherActor: RequestActor = {
      ...canonicalActor,
      userId: "user-2",
      authentication: { ...canonicalActor.authentication!, subject: "bob" },
    };
    const hijack = await handleSlackOauthCallback(
      new Request(
        `https://terminalx.example/api/connections/installations/slack/callback?code=c1&state=${encodeURIComponent(state)}`
      ),
      { ...deps, resolveActor: async () => otherActor }
    );
    expect(hijack.status).toBe(403);

    // The initiating actor completes it; the pending secret is single-use.
    const ok = await handleSlackOauthCallback(
      new Request(
        `https://terminalx.example/api/connections/installations/slack/callback?code=c1&state=${encodeURIComponent(state)}`
      ),
      deps
    );
    expect(ok.status).toBe(200);
    const json = (await ok.json()) as { installation: { id: string } };
    expect(json.installation.id).toBe("inst-slack");

    const replay = await handleSlackOauthCallback(
      new Request(
        `https://terminalx.example/api/connections/installations/slack/callback?code=c2&state=${encodeURIComponent(state)}`
      ),
      deps
    );
    expect(replay.status).toBe(410);
  });

  it("callback rejects a forged or expired state", async () => {
    const deps = slackDeps();
    const forged = await handleSlackOauthCallback(
      new Request(
        "https://terminalx.example/api/connections/installations/slack/callback?code=c&state=txsi_v1_forged.mac"
      ),
      deps
    );
    expect(forged.status).toBe(403);

    const expired = signInstallationState(
      {
        v: 1,
        intent: "install",
        provider: "slack",
        teamId: "team-1",
        userId: "user-1",
        credentialJtiDigest: "a".repeat(64),
        externalTenantId: "T1",
        externalAppId: "A1",
        redirectUri: "https://x/cb",
        nonce: "n",
        expiresAtMs: 999_999,
      },
      STATE_SECRET
    );
    const expiredRes = await handleSlackOauthCallback(
      new Request(
        `https://terminalx.example/api/connections/installations/slack/callback?code=c&state=${encodeURIComponent(expired)}`
      ),
      deps
    );
    expect(expiredRes.status).toBe(403);
  });
});

describe("telegram rotation route", () => {
  it("rotates through the exchange with the replaces linkage and records the new digest", async () => {
    const recorded: unknown[] = [];
    const exchangeCalls: Record<string, unknown>[] = [];
    const deps: InstallationHttpDependencies = {
      resolveActor: async () => canonicalActor,
      withConnectionDatabase: <T>(op: (db: never) => T): T =>
        op({
          prepare: (sql: string) => ({
            get: () => {
              if (sql.includes("team_memberships")) return { role: "admin" };
              return {
                id: "inst-1",
                team_id: "team-1",
                provider: "telegram",
                external_tenant_id: "998877",
                external_app_id: "998877",
                credential_handle_id: "txch_v1_" + "1".repeat(64),
                credential_handle_generation: 1,
                revision: 1,
              };
            },
            run: (...args: unknown[]) => {
              recorded.push(args);
              return { changes: 1 };
            },
          }),
        } as never),
      withConnectionAuthority: (op) =>
        op({
          rotateChannelInstallationCredential: () => ({
            id: "inst-1",
            revision: 2,
            status: "active",
          }),
        } as never),
      exchangeClient: {
        telegramBotToken: async (input) => {
          exchangeCalls.push(input as Record<string, unknown>);
          return {
            receipt: fakeReceipt(),
            botIdentity: {
              provider: "telegram",
              externalTenantId: "998877",
              externalAppId: "998877",
              botId: "998877",
              username: "bot",
            },
            webhookAuthDigest: "f".repeat(64),
          };
        },
        slackOauth: async () => {
          throw new Error("unused");
        },
        verifySlackWebhook: async () => ({ valid: false, withinReplayWindow: false }),
      },
      brokerClient: null,
      clock: () => 1_000_000,
      rateLimitState: new Map(),
    };
    const res = await handleRotateInstallation(
      new Request("https://terminalx.example/api/connections/installations/inst-1/rotate", {
        method: "POST",
        body: JSON.stringify({
          provider: "telegram",
          botToken: BOT_TOKEN,
          webhookBaseUrl: "https://terminalx.example",
          expectedRevision: 1,
          expectedHandleGeneration: 1,
        }),
      }),
      "inst-1",
      deps
    );
    expect(res.status).toBe(200);
    expect(await res.text()).not.toContain(BOT_TOKEN);
    expect(exchangeCalls[0]).toMatchObject({
      replaces: { handleId: "txch_v1_" + "1".repeat(64) },
    });
    // The new webhook auth digest row was written.
    expect(recorded.some((args) => JSON.stringify(args).includes("f".repeat(64)))).toBe(true);
  });
});
