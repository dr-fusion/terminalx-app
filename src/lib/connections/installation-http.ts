import { createHmac, randomBytes as cryptoRandomBytes, timingSafeEqual } from "node:crypto";
import crypto from "node:crypto";
import type Database from "better-sqlite3";
import { resolveRequestActor, type RequestActor, type RequestHeaders } from "../request-actor";
import { connectionActorSnapshot } from "./request-actor";
import {
  withConnectionAuthority as defaultWithConnectionAuthority,
  withConnectionDatabase as defaultWithConnectionDatabase,
} from "../identity-service";
import {
  resolveConfiguredSecretBrokerClient,
  configuredSecretBrokerRoot,
} from "./secret-broker-composition";
import {
  createProviderExchangeClient,
  type ProviderExchangeClient,
} from "./provider-exchange-client";
import type { SecretBrokerClient } from "./secret-broker-client";
import type { ConnectionAuthority } from "./authority";
import type { ConnectionActorSnapshot } from "./contracts";
import { secretBrokerExpectationDigest } from "./secret-broker-shared";
import { createWebhookAuthStore } from "./webhook-auth";
import {
  SLACK_BOT_SCOPES,
  SLACK_INSTALLATION_CAPABILITIES,
  SLACK_INSTALLATION_REVIEWED_SCOPES,
  TELEGRAM_INSTALLATION_CAPABILITIES,
  TELEGRAM_INSTALLATION_REVIEWED_SCOPES,
} from "./providers/scopes";
import { findActiveInstallationById } from "./read-model";
import { join } from "node:path";

/**
 * Installation acquisition routes (Slice 8E follow-up). Creation and rotation run
 * behind an authenticated canonical actor; Team owner/admin authority and the
 * live-session gate are enforced inside the connection authority transaction (a
 * defense-in-depth membership pre-check runs here too, so a non-admin never
 * reaches the broker exchange).
 *
 * Telegram: the operator-supplied bot token is INPUT-ONLY on this one HTTPS,
 * authenticated route. It is forwarded to the broker exchange and never echoed,
 * logged, audited, or persisted in main-process state (ADR 0004 residual).
 * Creation is additionally rate limited per User (rolling hour) and every
 * attempt emits a secret-free audit event.
 *
 * Slack: redirect-based. The start call returns a signed, single-use `state`
 * bound to the initiating actor (user id + credential JTI digest) with a bounded
 * expiry; the OAuth callback verifies the state against the live actor before
 * exchanging the code inside the broker. The app signing secret provided at
 * start is held only in a bounded, TTL'd, single-use in-memory pending store —
 * never persisted, never placed in the state.
 */
export class InstallationHttpProblem extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string
  ) {
    super(message);
    this.name = "InstallationHttpProblem";
  }
}

const STATE_PREFIX = "txsi_v1_";
const STATE_TTL_MS = 10 * 60 * 1000;
const PENDING_SECRET_LIMIT = 64;
const TELEGRAM_CREATE_LIMIT_PER_HOUR = 5;
const RATE_WINDOW_MS = 60 * 60 * 1000;
const MAX_BODY_BYTES = 64 * 1024;

export interface InstallStatePayload {
  readonly v: 1;
  readonly intent: "install" | "rotate";
  readonly provider: "slack";
  readonly teamId: string;
  readonly userId: string;
  readonly credentialJtiDigest: string;
  readonly externalTenantId: string;
  readonly externalAppId: string;
  readonly redirectUri: string;
  readonly nonce: string;
  readonly expiresAtMs: number;
  readonly installationId?: string;
  readonly expectedRevision?: number;
  readonly expectedHandleGeneration?: number;
  readonly replacesHandleId?: string;
}

export function signInstallationState(payload: InstallStatePayload, secret: string): string {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const mac = createHmac("sha256", secret)
    .update(`${STATE_PREFIX}${body}`, "utf8")
    .digest("base64url");
  return `${STATE_PREFIX}${body}.${mac}`;
}

export function verifyInstallationState(
  state: unknown,
  secret: string,
  nowMs: number
): InstallStatePayload | null {
  if (typeof state !== "string" || state.length > 4096 || !state.startsWith(STATE_PREFIX)) {
    return null;
  }
  const dot = state.lastIndexOf(".");
  if (dot <= STATE_PREFIX.length) return null;
  const signedPart = state.slice(0, dot);
  const mac = state.slice(dot + 1);
  const expected = createHmac("sha256", secret).update(signedPart, "utf8").digest("base64url");
  const macBuffer = Buffer.from(mac, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  if (macBuffer.byteLength !== expectedBuffer.byteLength) return null;
  if (!timingSafeEqual(macBuffer, expectedBuffer)) return null;
  let payload: InstallStatePayload;
  try {
    payload = JSON.parse(
      Buffer.from(signedPart.slice(STATE_PREFIX.length), "base64url").toString("utf8")
    ) as InstallStatePayload;
  } catch {
    return null;
  }
  if (
    payload?.v !== 1 ||
    payload.provider !== "slack" ||
    (payload.intent !== "install" && payload.intent !== "rotate") ||
    typeof payload.nonce !== "string" ||
    !Number.isSafeInteger(payload.expiresAtMs) ||
    nowMs >= payload.expiresAtMs
  ) {
    return null;
  }
  return payload;
}

/** Bounded, TTL'd, single-use in-memory store for pending Slack signing secrets. */
export interface PendingSlackSecretStore {
  put(nonce: string, signingSecret: string, expiresAtMs: number): void;
  /** Removes and returns the secret; a second take fails (single use). */
  take(nonce: string, nowMs: number): string | null;
}

export function createPendingSlackSecretStore(): PendingSlackSecretStore {
  const entries = new Map<string, { secret: string; expiresAtMs: number }>();
  return Object.freeze({
    put(nonce: string, signingSecret: string, expiresAtMs: number): void {
      for (const [key, entry] of entries) {
        if (entry.expiresAtMs <= Date.now()) entries.delete(key);
      }
      if (entries.size >= PENDING_SECRET_LIMIT) {
        throw new InstallationHttpProblem(429, "too-many-pending", "too many pending installs");
      }
      entries.set(nonce, { secret: signingSecret, expiresAtMs });
    },
    take(nonce: string, nowMs: number): string | null {
      const entry = entries.get(nonce);
      entries.delete(nonce);
      if (!entry || entry.expiresAtMs <= nowMs) return null;
      return entry.secret;
    },
  });
}

export interface InstallationAuditEvent {
  readonly action:
    | "installation.create.telegram"
    | "installation.create.slack-start"
    | "installation.create.slack-complete"
    | "installation.rotate.telegram"
    | "installation.rotate.slack-start"
    | "installation.rotate.slack-complete";
  readonly outcome: "ok" | "denied" | "failed";
  readonly teamId?: string;
  readonly installationId?: string;
  readonly userId?: string;
}

export interface InstallationHttpDependencies {
  resolveActor?: (headers: RequestHeaders) => Promise<RequestActor | null>;
  withConnectionAuthority?: <T>(operation: (authority: ConnectionAuthority) => T) => T;
  withConnectionDatabase?: <T>(operation: (db: Database.Database) => T) => T;
  exchangeClient?: ProviderExchangeClient | null;
  brokerClient?: SecretBrokerClient | null;
  /** HMAC key for the Slack OAuth state; production uses TERMINALX_JWT_SECRET. */
  stateSecret?: () => string | null;
  pendingSlackSecrets?: PendingSlackSecretStore;
  slackClientId?: () => string | null;
  clock?: () => number;
  idGenerator?: () => string;
  nonceGenerator?: () => string;
  audit?: (event: InstallationAuditEvent) => void;
  /** Rolling-hour Telegram-create attempts per user; injectable for tests. */
  rateLimitState?: Map<string, number[]>;
}

const defaultPendingSecrets = createPendingSlackSecretStore();
const defaultRateLimitState = new Map<string, number[]>();

function resolveDefaultExchangeClient(): ProviderExchangeClient | null {
  const rootDir = configuredSecretBrokerRoot();
  if (!rootDir) return null;
  return createProviderExchangeClient({ socketPath: join(rootDir, "broker.sock") });
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

async function withErrors(fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (error) {
    if (error instanceof InstallationHttpProblem) {
      return jsonResponse({ error: { code: error.code } }, error.status);
    }
    const message = error instanceof Error ? error.message : "";
    if (/authority is required|owner or admin|membership is required/i.test(message)) {
      return jsonResponse({ error: { code: "not-authorized" } }, 403);
    }
    if (/authentication session is unavailable|snapshot is stale/i.test(message)) {
      return jsonResponse({ error: { code: "authentication-required" } }, 403);
    }
    if (/was fenced|revision is stale|reused the handle/i.test(message)) {
      return jsonResponse({ error: { code: "conflict" } }, 409);
    }
    if (/unavailable|not-ready|not found/i.test(message)) {
      return jsonResponse({ error: { code: "connection-unavailable" } }, 503);
    }
    return jsonResponse({ error: { code: "invalid-request" } }, 400);
  }
}

async function requireActor(
  request: Request,
  deps: InstallationHttpDependencies
): Promise<ConnectionActorSnapshot> {
  const resolve = deps.resolveActor ?? resolveRequestActor;
  const actor = await resolve(request.headers as unknown as RequestHeaders);
  const snapshot = actor ? connectionActorSnapshot(actor) : null;
  if (!snapshot) {
    throw new InstallationHttpProblem(401, "authentication-required", "auth required");
  }
  return snapshot;
}

function assertMutationOrigin(request: Request): void {
  const cookie = request.headers.get("cookie");
  if (!cookie || !cookie.includes("terminalx-session")) return;
  const origin = request.headers.get("origin");
  const host = request.headers.get("host");
  if (origin) {
    let originHost: string;
    try {
      originHost = new URL(origin).host;
    } catch {
      throw new InstallationHttpProblem(403, "forbidden-origin", "bad origin");
    }
    if (host && originHost !== host) {
      throw new InstallationHttpProblem(403, "forbidden-origin", "cross-origin");
    }
  }
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf8") > MAX_BODY_BYTES) {
    throw new InstallationHttpProblem(413, "body-too-large", "body too large");
  }
  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    throw new InstallationHttpProblem(400, "invalid-json", "invalid JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new InstallationHttpProblem(400, "invalid-request", "object body required");
  }
  return body as Record<string, unknown>;
}

function requireString(value: unknown, code: string, maxLength = 1024): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maxLength) {
    throw new InstallationHttpProblem(400, code, "invalid field");
  }
  return value;
}

function requireHttpsUrl(value: unknown, code: string): string {
  const raw = requireString(value, code, 2048);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new InstallationHttpProblem(400, code, "invalid URL");
  }
  if (url.protocol !== "https:") {
    throw new InstallationHttpProblem(400, code, "https required");
  }
  return raw.replace(/\/+$/, "");
}

function requirePositiveInt(value: unknown, code: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new InstallationHttpProblem(400, code, "invalid version");
  }
  return value as number;
}

function requireAdminMembership(
  deps: InstallationHttpDependencies,
  teamId: string,
  userId: string
): void {
  const withDb = deps.withConnectionDatabase ?? defaultWithConnectionDatabase;
  const row = withDb((db) =>
    db
      .prepare(
        `SELECT role FROM team_memberships
         WHERE team_id = ? AND user_id = ? AND status = 'active'`
      )
      .get(teamId, userId)
  ) as { role: string } | undefined;
  if (!row || (row.role !== "owner" && row.role !== "admin")) {
    throw new InstallationHttpProblem(403, "not-authorized", "owner/admin required");
  }
}

function requireExchange(deps: InstallationHttpDependencies): ProviderExchangeClient {
  const client =
    deps.exchangeClient === undefined ? resolveDefaultExchangeClient() : deps.exchangeClient;
  if (!client) {
    throw new InstallationHttpProblem(503, "connection-unavailable", "broker not configured");
  }
  return client;
}

function brokerClient(deps: InstallationHttpDependencies): SecretBrokerClient | null {
  return deps.brokerClient === undefined
    ? resolveConfiguredSecretBrokerClient()
    : deps.brokerClient;
}

function requireStateSecret(deps: InstallationHttpDependencies): string {
  const secret = deps.stateSecret ? deps.stateSecret() : (process.env.TERMINALX_JWT_SECRET ?? null);
  if (!secret || secret.length < 16) {
    throw new InstallationHttpProblem(503, "connection-unavailable", "state secret unavailable");
  }
  return secret;
}

function enforceTelegramCreateRate(
  deps: InstallationHttpDependencies,
  userId: string,
  now: number
): void {
  const state = deps.rateLimitState ?? defaultRateLimitState;
  const attempts = (state.get(userId) ?? []).filter((at) => now - at < RATE_WINDOW_MS);
  if (attempts.length >= TELEGRAM_CREATE_LIMIT_PER_HOUR) {
    throw new InstallationHttpProblem(429, "rate-limited", "too many installation attempts");
  }
  attempts.push(now);
  state.set(userId, attempts);
}

/** POST /api/connections/installations */
export async function handleCreateInstallation(
  request: Request,
  deps: InstallationHttpDependencies = {}
): Promise<Response> {
  return withErrors(async () => {
    const actor = await requireActor(request, deps);
    assertMutationOrigin(request);
    const body = await readJson(request);
    if (body.provider === "telegram") return createTelegramInstallation(actor, body, deps);
    if (body.provider === "slack") return startSlackFlow(actor, body, deps, "install");
    throw new InstallationHttpProblem(400, "invalid-provider", "unsupported provider");
  });
}

/** POST /api/connections/installations/[installationId]/rotate */
export async function handleRotateInstallation(
  request: Request,
  installationId: string,
  deps: InstallationHttpDependencies = {}
): Promise<Response> {
  return withErrors(async () => {
    const actor = await requireActor(request, deps);
    assertMutationOrigin(request);
    const body = await readJson(request);
    if (body.provider === "telegram") {
      return rotateTelegramInstallation(actor, installationId, body, deps);
    }
    if (body.provider === "slack") {
      return startSlackFlow(actor, { ...body, installationId }, deps, "rotate");
    }
    throw new InstallationHttpProblem(400, "invalid-provider", "unsupported provider");
  });
}

async function createTelegramInstallation(
  actor: ConnectionActorSnapshot,
  body: Record<string, unknown>,
  deps: InstallationHttpDependencies
): Promise<Response> {
  const clock = deps.clock ?? Date.now;
  const audit = deps.audit ?? (() => undefined);
  const teamId = requireString(body.teamId, "invalid-team", 300);
  const botId = requireString(body.botId, "invalid-bot-id", 64);
  // INPUT-ONLY: forwarded to the broker exchange, never echoed/logged/persisted.
  const botToken = requireString(body.botToken, "invalid-bot-token", 4096);
  const webhookBaseUrl = requireHttpsUrl(body.webhookBaseUrl, "invalid-webhook-base");
  try {
    requireAdminMembership(deps, teamId, actor.userId);
    enforceTelegramCreateRate(deps, actor.userId, clock());
    const exchange = requireExchange(deps);
    const installationId = (deps.idGenerator ?? crypto.randomUUID)();
    const expectation = Object.freeze({
      provider: "telegram" as const,
      brokerKind: "oauth-envelope" as const,
      usage: "installation" as const,
      authorityBinding: Object.freeze({
        kind: "installation" as const,
        teamId,
        externalTenantId: botId,
        externalAppId: botId,
      }),
      replaces: null,
    });
    const acquired = await exchange.telegramBotToken({
      botToken,
      expectedTenantId: botId,
      expectedAppId: botId,
      webhookUrl: `${webhookBaseUrl}/api/connections/webhooks/telegram/${installationId}`,
      expectationDigest: secretBrokerExpectationDigest(expectation),
    });
    const withAuthority = deps.withConnectionAuthority ?? defaultWithConnectionAuthority;
    let installation;
    try {
      installation = withAuthority((authority) =>
        authority.createChannelInstallation({
          actor,
          teamId,
          provider: "telegram",
          externalTenantId: botId,
          externalAppId: botId,
          expectedBrokerKind: "oauth-envelope",
          credentialBrokerProof: acquired.receipt,
          reviewedScopes: TELEGRAM_INSTALLATION_REVIEWED_SCOPES,
          capabilities: TELEGRAM_INSTALLATION_CAPABILITIES,
          installationId,
        })
      );
    } catch (error) {
      // The authority did not commit; abort the pending broker registration.
      // The broker TTL reap + reconciler converge if this abort itself fails.
      await brokerClient(deps)
        ?.abortRegistration(acquired.receipt.payload.receiptId)
        .catch(() => undefined);
      throw error;
    }
    const withDb = deps.withConnectionDatabase ?? defaultWithConnectionDatabase;
    withDb((db) =>
      createWebhookAuthStore(db).recordWebhookAuthDigest({
        installationId: installation.id,
        provider: "telegram",
        authDigest: acquired.webhookAuthDigest,
        createdAtMs: clock(),
      })
    );
    await brokerClient(deps)
      ?.finalizeRegistration(acquired.receipt.payload.handleId, acquired.receipt.payload.receiptId)
      .catch(() => undefined);
    audit({
      action: "installation.create.telegram",
      outcome: "ok",
      teamId,
      installationId: installation.id,
      userId: actor.userId,
    });
    return jsonResponse({ installation, botIdentity: acquired.botIdentity }, 201);
  } catch (error) {
    audit({
      action: "installation.create.telegram",
      outcome:
        error instanceof InstallationHttpProblem && error.status === 403 ? "denied" : "failed",
      teamId,
      userId: actor.userId,
    });
    throw error;
  }
}

async function rotateTelegramInstallation(
  actor: ConnectionActorSnapshot,
  installationId: string,
  body: Record<string, unknown>,
  deps: InstallationHttpDependencies
): Promise<Response> {
  const clock = deps.clock ?? Date.now;
  const audit = deps.audit ?? (() => undefined);
  // INPUT-ONLY, exactly like creation.
  const botToken = requireString(body.botToken, "invalid-bot-token", 4096);
  const webhookBaseUrl = requireHttpsUrl(body.webhookBaseUrl, "invalid-webhook-base");
  const expectedRevision = requirePositiveInt(body.expectedRevision, "invalid-revision");
  const expectedHandleGeneration = requirePositiveInt(
    body.expectedHandleGeneration,
    "invalid-generation"
  );
  const withDb = deps.withConnectionDatabase ?? defaultWithConnectionDatabase;
  const snapshot = withDb((db) => findActiveInstallationById(db, installationId, "telegram"));
  if (!snapshot) throw new InstallationHttpProblem(404, "not-found", "installation unavailable");
  try {
    requireAdminMembership(deps, snapshot.teamId, actor.userId);
    enforceTelegramCreateRate(deps, actor.userId, clock());
    const exchange = requireExchange(deps);
    const expectation = Object.freeze({
      provider: "telegram" as const,
      brokerKind: "oauth-envelope" as const,
      usage: "installation" as const,
      authorityBinding: Object.freeze({
        kind: "installation" as const,
        teamId: snapshot.teamId,
        externalTenantId: snapshot.externalTenantId,
        externalAppId: snapshot.externalAppId,
      }),
      // The authority revokes the old handle first, so the receipt must bind the
      // post-revocation generation.
      replaces: Object.freeze({
        handleId: snapshot.credentialHandleId,
        generation: expectedHandleGeneration + 1,
      }),
    });
    const acquired = await exchange.telegramBotToken({
      botToken,
      expectedTenantId: snapshot.externalTenantId,
      expectedAppId: snapshot.externalAppId,
      webhookUrl: `${webhookBaseUrl}/api/connections/webhooks/telegram/${installationId}`,
      expectationDigest: secretBrokerExpectationDigest(expectation),
      replaces: { handleId: snapshot.credentialHandleId },
    });
    const withAuthority = deps.withConnectionAuthority ?? defaultWithConnectionAuthority;
    let installation;
    try {
      installation = withAuthority((authority) =>
        authority.rotateChannelInstallationCredential({
          actor,
          installationId,
          expectedRevision,
          expectedHandleGeneration,
          brokerProof: acquired.receipt,
        })
      );
    } catch (error) {
      await brokerClient(deps)
        ?.abortRotation(acquired.receipt.payload.receiptId)
        .catch(() => undefined);
      throw error;
    }
    withDb((db) =>
      createWebhookAuthStore(db).recordWebhookAuthDigest({
        installationId,
        provider: "telegram",
        authDigest: acquired.webhookAuthDigest,
        createdAtMs: clock(),
      })
    );
    await brokerClient(deps)
      ?.finalizeRotation(acquired.receipt.payload.handleId, acquired.receipt.payload.receiptId)
      .catch(() => undefined);
    audit({
      action: "installation.rotate.telegram",
      outcome: "ok",
      teamId: snapshot.teamId,
      installationId,
      userId: actor.userId,
    });
    return jsonResponse({ installation });
  } catch (error) {
    audit({
      action: "installation.rotate.telegram",
      outcome:
        error instanceof InstallationHttpProblem && error.status === 403 ? "denied" : "failed",
      teamId: snapshot.teamId,
      installationId,
      userId: actor.userId,
    });
    throw error;
  }
}

function startSlackFlow(
  actor: ConnectionActorSnapshot,
  body: Record<string, unknown>,
  deps: InstallationHttpDependencies,
  intent: "install" | "rotate"
): Response {
  const clock = deps.clock ?? Date.now;
  const audit = deps.audit ?? (() => undefined);
  const now = clock();
  const secret = requireStateSecret(deps);
  // The signing secret is held only in the bounded single-use pending store.
  const signingSecret = requireString(body.signingSecret, "invalid-signing-secret", 4096);
  const redirectUri = requireHttpsUrl(body.redirectUri, "invalid-redirect-uri");

  let teamId: string;
  let externalTenantId: string;
  let externalAppId: string;
  let rotate: {
    installationId: string;
    expectedRevision: number;
    expectedHandleGeneration: number;
    replacesHandleId: string;
  } | null = null;
  if (intent === "install") {
    teamId = requireString(body.teamId, "invalid-team", 300);
    externalTenantId = requireString(body.externalTenantId, "invalid-tenant", 1024);
    externalAppId = requireString(body.externalAppId, "invalid-app", 1024);
  } else {
    const installationId = requireString(body.installationId, "invalid-installation", 300);
    const withDb = deps.withConnectionDatabase ?? defaultWithConnectionDatabase;
    const snapshot = withDb((db) => findActiveInstallationById(db, installationId, "slack"));
    if (!snapshot) throw new InstallationHttpProblem(404, "not-found", "installation unavailable");
    teamId = snapshot.teamId;
    externalTenantId = snapshot.externalTenantId;
    externalAppId = snapshot.externalAppId;
    rotate = {
      installationId,
      expectedRevision: requirePositiveInt(body.expectedRevision, "invalid-revision"),
      expectedHandleGeneration: requirePositiveInt(
        body.expectedHandleGeneration,
        "invalid-generation"
      ),
      replacesHandleId: snapshot.credentialHandleId,
    };
  }
  requireAdminMembership(deps, teamId, actor.userId);

  const nonce = (deps.nonceGenerator ?? (() => cryptoRandomBytes(24).toString("base64url")))();
  const expiresAtMs = now + STATE_TTL_MS;
  (deps.pendingSlackSecrets ?? defaultPendingSecrets).put(nonce, signingSecret, expiresAtMs);
  const payload: InstallStatePayload = {
    v: 1,
    intent,
    provider: "slack",
    teamId,
    userId: actor.userId,
    credentialJtiDigest: actor.credentialJtiDigest,
    externalTenantId,
    externalAppId,
    redirectUri,
    nonce,
    expiresAtMs,
    ...(rotate
      ? {
          installationId: rotate.installationId,
          expectedRevision: rotate.expectedRevision,
          expectedHandleGeneration: rotate.expectedHandleGeneration,
          replacesHandleId: rotate.replacesHandleId,
        }
      : {}),
  };
  const state = signInstallationState(payload, secret);
  const clientId = deps.slackClientId
    ? deps.slackClientId()
    : (process.env.TERMINALX_SLACK_CLIENT_ID ?? null);
  const authorizeUrl = new URL("https://slack.com/oauth/v2/authorize");
  if (clientId) authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("scope", SLACK_BOT_SCOPES.join(","));
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("state", state);
  audit({
    action:
      intent === "install" ? "installation.create.slack-start" : "installation.rotate.slack-start",
    outcome: "ok",
    teamId,
    userId: actor.userId,
    ...(rotate ? { installationId: rotate.installationId } : {}),
  });
  return jsonResponse({ authorizeUrl: authorizeUrl.toString(), state, expiresAtMs });
}

/** GET /api/connections/installations/slack/callback?code=…&state=… */
export async function handleSlackOauthCallback(
  request: Request,
  deps: InstallationHttpDependencies = {}
): Promise<Response> {
  return withErrors(async () => {
    const actor = await requireActor(request, deps);
    const clock = deps.clock ?? Date.now;
    const audit = deps.audit ?? (() => undefined);
    const url = new URL(request.url);
    const code = url.searchParams.get("code") ?? "";
    const stateRaw = url.searchParams.get("state") ?? "";
    if (code.length < 1 || code.length > 4096) {
      throw new InstallationHttpProblem(400, "invalid-code", "missing code");
    }
    const secret = requireStateSecret(deps);
    const state = verifyInstallationState(stateRaw, secret, clock());
    if (!state) throw new InstallationHttpProblem(403, "invalid-state", "state rejected");
    // The callback must be completed by the same authenticated actor that
    // started the flow, under the same credential.
    if (state.userId !== actor.userId || state.credentialJtiDigest !== actor.credentialJtiDigest) {
      throw new InstallationHttpProblem(403, "invalid-state", "state actor mismatch");
    }
    const signingSecret = (deps.pendingSlackSecrets ?? defaultPendingSecrets).take(
      state.nonce,
      clock()
    );
    if (!signingSecret) {
      throw new InstallationHttpProblem(410, "state-expired", "pending install unavailable");
    }
    const exchange = requireExchange(deps);
    const rotation = state.intent === "rotate";
    const expectation = Object.freeze({
      provider: "slack" as const,
      brokerKind: "oauth-envelope" as const,
      usage: "installation" as const,
      authorityBinding: Object.freeze({
        kind: "installation" as const,
        teamId: state.teamId,
        externalTenantId: state.externalTenantId,
        externalAppId: state.externalAppId,
      }),
      replaces: rotation
        ? Object.freeze({
            handleId: state.replacesHandleId as string,
            generation: (state.expectedHandleGeneration as number) + 1,
          })
        : null,
    });
    const acquired = await exchange.slackOauth({
      code,
      expectedTenantId: state.externalTenantId,
      expectedAppId: state.externalAppId,
      expectationDigest: secretBrokerExpectationDigest(expectation),
      signingSecret,
      redirectUri: state.redirectUri,
      ...(rotation ? { replaces: { handleId: state.replacesHandleId as string } } : {}),
    });
    const withAuthority = deps.withConnectionAuthority ?? defaultWithConnectionAuthority;
    let installation;
    try {
      installation = withAuthority((authority) =>
        rotation
          ? authority.rotateChannelInstallationCredential({
              actor,
              installationId: state.installationId as string,
              expectedRevision: state.expectedRevision as number,
              expectedHandleGeneration: state.expectedHandleGeneration as number,
              brokerProof: acquired.receipt,
            })
          : authority.createChannelInstallation({
              actor,
              teamId: state.teamId,
              provider: "slack",
              externalTenantId: state.externalTenantId,
              externalAppId: state.externalAppId,
              expectedBrokerKind: "oauth-envelope",
              credentialBrokerProof: acquired.receipt,
              reviewedScopes: SLACK_INSTALLATION_REVIEWED_SCOPES,
              capabilities: SLACK_INSTALLATION_CAPABILITIES,
            })
      );
    } catch (error) {
      const client = brokerClient(deps);
      await (
        rotation
          ? client?.abortRotation(acquired.receipt.payload.receiptId)
          : client?.abortRegistration(acquired.receipt.payload.receiptId)
      )?.catch(() => undefined);
      audit({
        action: rotation
          ? "installation.rotate.slack-complete"
          : "installation.create.slack-complete",
        outcome: "failed",
        teamId: state.teamId,
        userId: actor.userId,
      });
      throw error;
    }
    const client = brokerClient(deps);
    await (
      rotation
        ? client?.finalizeRotation(
            acquired.receipt.payload.handleId,
            acquired.receipt.payload.receiptId
          )
        : client?.finalizeRegistration(
            acquired.receipt.payload.handleId,
            acquired.receipt.payload.receiptId
          )
    )?.catch(() => undefined);
    audit({
      action: rotation
        ? "installation.rotate.slack-complete"
        : "installation.create.slack-complete",
      outcome: "ok",
      teamId: state.teamId,
      installationId: installation.id,
      userId: actor.userId,
    });
    return jsonResponse({ installation, slackInstallation: acquired.installation });
  });
}
