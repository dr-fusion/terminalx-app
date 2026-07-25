import { SecretBrokerProtocolError } from "../protocol";

/**
 * The provider-exchange network seam. This is the only place in the Secret Broker
 * that performs the credential-acquisition network calls (Slack `oauth.v2.access`,
 * Telegram `getMe`/`setWebhook`). It runs entirely inside the broker process, so
 * the acquired bot token never crosses the socket. Production uses
 * {@link createFetchProviderExchangeClient}; tests inject a hermetic fake pointed
 * at a localhost server.
 *
 * Every method fails closed: a network/transport failure or a provider decline is
 * surfaced as a bounded {@link ProviderExchangeError}, never as raw upstream text.
 */
export type ProviderExchangeErrorKind =
  | "transport"
  | "provider-declined"
  | "invalid-response"
  | "tls-required";

export class ProviderExchangeError extends Error {
  readonly kind: ProviderExchangeErrorKind;
  constructor(kind: ProviderExchangeErrorKind) {
    super(`provider exchange error: ${kind}`);
    this.kind = kind;
    this.name = "ProviderExchangeError";
  }
}

export interface SlackOauthAccessInput {
  /** The single-use OAuth authorization code. Input-only; never persisted or logged. */
  readonly code: string;
  readonly redirectUri?: string;
}

export interface SlackOauthAccessResult {
  /** The acquired bot token. Sealed inside the broker; never returned over the socket. */
  readonly botToken: string;
  readonly teamId: string;
  readonly appId: string;
  readonly botUserId: string;
  readonly grantedScopes: readonly string[];
}

export interface TelegramGetMeResult {
  readonly botId: string;
  readonly username: string;
}

export interface SlackOidcJwk {
  readonly kid: string;
  readonly kty: string;
  readonly alg?: string;
  readonly n: string;
  readonly e: string;
  readonly use?: string;
}

export interface ProviderExchangeClient {
  slackOauthAccess(input: SlackOauthAccessInput): Promise<SlackOauthAccessResult>;
  telegramGetMe(botToken: string): Promise<TelegramGetMeResult>;
  telegramSetWebhook(botToken: string, webhookUrl: string, secretToken: string): Promise<void>;
  /** Fetch Slack's OpenID Connect JWKS for in-broker id_token verification. */
  fetchSlackOidcJwks(): Promise<{ readonly keys: readonly SlackOidcJwk[] }>;
}

export interface CreateFetchProviderExchangeClientOptions {
  readonly fetchImpl?: typeof fetch;
  /** Resolve a provider host to a request origin; defaults to `https://<host>`. */
  readonly resolveOrigin?: (host: string) => string;
  /** Slack OAuth client id/secret from the reviewed app configuration. */
  readonly slackClientId?: string;
  readonly slackClientSecret?: string;
  readonly requestTimeoutMs?: number;
}

const LOOPBACK_HOSTS = Object.freeze(["127.0.0.1", "localhost", "[::1]", "::1"]);
const MAX_RESPONSE_BYTES = 64 * 1024;

/**
 * The shipped real exchange client. TLS is required unless the resolved origin is
 * an explicit loopback test origin; redirects are never followed; the response is
 * bounded before parsing. It never logs request or response bodies.
 */
export function createFetchProviderExchangeClient(
  options: CreateFetchProviderExchangeClientOptions = {}
): ProviderExchangeClient {
  const doFetch = options.fetchImpl ?? fetch;
  const resolveOrigin = options.resolveOrigin ?? ((host: string) => `https://${host}`);
  const timeoutMs = options.requestTimeoutMs ?? 10_000;

  async function call(
    host: string,
    path: string,
    method: "GET" | "POST",
    body: Record<string, string> | null
  ): Promise<Record<string, unknown>> {
    const origin = resolveOrigin(host);
    let url: URL;
    try {
      url = new URL(path, origin);
    } catch {
      throw new ProviderExchangeError("transport");
    }
    const isLoopback = LOOPBACK_HOSTS.includes(url.hostname);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback)) {
      throw new ProviderExchangeError("tls-required");
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    timer.unref?.();
    let response: Response;
    try {
      response = await doFetch(url, {
        method,
        headers: body ? { "content-type": "application/x-www-form-urlencoded" } : {},
        body: body ? new URLSearchParams(body).toString() : undefined,
        redirect: "manual",
        signal: controller.signal,
      });
    } catch {
      throw new ProviderExchangeError("transport");
    } finally {
      clearTimeout(timer);
    }
    if (response.status >= 300) throw new ProviderExchangeError("transport");
    const text = await readCapped(response);
    try {
      const parsed = JSON.parse(text) as unknown;
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new ProviderExchangeError("invalid-response");
      }
      return parsed as Record<string, unknown>;
    } catch (error) {
      if (error instanceof ProviderExchangeError) throw error;
      throw new ProviderExchangeError("invalid-response");
    }
  }

  return Object.freeze({
    async slackOauthAccess(input: SlackOauthAccessInput): Promise<SlackOauthAccessResult> {
      const form: Record<string, string> = { code: input.code };
      if (options.slackClientId) form.client_id = options.slackClientId;
      if (options.slackClientSecret) form.client_secret = options.slackClientSecret;
      if (input.redirectUri) form.redirect_uri = input.redirectUri;
      const json = await call("slack.com", "/api/oauth.v2.access", "POST", form);
      if (json.ok !== true) throw new ProviderExchangeError("provider-declined");
      const botToken = typeof json.access_token === "string" ? json.access_token : null;
      const team = asRecord(json.team);
      const appId = typeof json.app_id === "string" ? json.app_id : null;
      const botUserId = typeof json.bot_user_id === "string" ? json.bot_user_id : null;
      const scope = typeof json.scope === "string" ? json.scope : "";
      const teamId = team && typeof team.id === "string" ? team.id : null;
      if (!botToken || !appId || !botUserId || !teamId) {
        throw new ProviderExchangeError("invalid-response");
      }
      return Object.freeze({
        botToken,
        teamId,
        appId,
        botUserId,
        grantedScopes: Object.freeze(scope.length > 0 ? scope.split(",") : []),
      });
    },
    async telegramGetMe(botToken: string): Promise<TelegramGetMeResult> {
      const json = await call("api.telegram.org", `/bot${botToken}/getMe`, "GET", null);
      if (json.ok !== true) throw new ProviderExchangeError("provider-declined");
      const result = asRecord(json.result);
      const botId = result && Number.isSafeInteger(result.id) ? String(result.id) : null;
      const username = result && typeof result.username === "string" ? result.username : null;
      if (!botId || !username) throw new ProviderExchangeError("invalid-response");
      return Object.freeze({ botId, username });
    },
    async telegramSetWebhook(
      botToken: string,
      webhookUrl: string,
      secretToken: string
    ): Promise<void> {
      const json = await call("api.telegram.org", `/bot${botToken}/setWebhook`, "POST", {
        url: webhookUrl,
        secret_token: secretToken,
      });
      if (json.ok !== true) throw new ProviderExchangeError("provider-declined");
    },
    async fetchSlackOidcJwks(): Promise<{ readonly keys: readonly SlackOidcJwk[] }> {
      const json = await call("slack.com", "/openid/connect/keys", "GET", null);
      const keys = json.keys;
      if (!Array.isArray(keys)) throw new ProviderExchangeError("invalid-response");
      return { keys: keys as readonly SlackOidcJwk[] };
    },
  });
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

async function readCapped(response: Response): Promise<string> {
  const stream = response.body;
  if (!stream) return "";
  const reader = stream.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        const chunk = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
        total += chunk.byteLength;
        if (total > MAX_RESPONSE_BYTES) throw new SecretBrokerProtocolError("invalid-request");
        chunks.push(chunk);
      }
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, total).toString("utf8");
}
