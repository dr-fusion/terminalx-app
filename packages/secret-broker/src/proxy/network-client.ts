/**
 * The Credential Proxy network seam. The proxy hands a fully-built outbound
 * request — including the attached credential in the URL path (Telegram) or the
 * Authorization header (Slack) — to a {@link ProxyNetworkClient}. The client is
 * the only place that performs real network I/O, and it never logs. Production
 * uses {@link createFetchProxyNetworkClient}; tests inject a hermetic fake.
 *
 * The client enforces the effect-boundary rules that cannot be delegated to the
 * caller: TLS only (loopback http is permitted solely for a configured test
 * origin), redirects are never followed, no environment proxy is honored, the
 * response size cap is enforced before buffering, and an ambiguous outcome (a
 * timeout after the request was dispatched) is surfaced, never silently dropped.
 */
export type ProxyNetworkErrorKind =
  | "timeout-before-response"
  | "timeout-after-send"
  | "transport"
  | "redirect"
  | "response-too-large"
  | "tls-required";

export class ProxyNetworkError extends Error {
  readonly kind: ProxyNetworkErrorKind;
  constructor(kind: ProxyNetworkErrorKind) {
    // The message is fixed per kind and never derived from an upstream response.
    super(`proxy network error: ${kind}`);
    this.kind = kind;
    this.name = "ProxyNetworkError";
  }
}

export interface ProxyOutboundRequest {
  readonly method: "GET" | "POST";
  /** Resolved origin, e.g. `https://api.telegram.org`. */
  readonly origin: string;
  /** Path beginning with `/`. May embed the credential (Telegram bot path). */
  readonly path: string;
  readonly query: Readonly<Record<string, string>>;
  /** Headers including any credential header (Slack bearer). Never logged. */
  readonly headers: Readonly<Record<string, string>>;
  /** Serialized request body (JSON text) or null. */
  readonly body: string | null;
  readonly maxResponseBytes: number;
  readonly timeoutMs: number;
}

export interface ProxyNetworkResponse {
  readonly status: number;
  readonly body: Buffer;
}

export interface ProxyNetworkClient {
  send(request: ProxyOutboundRequest): Promise<ProxyNetworkResponse>;
}

const LOOPBACK_HOSTS = Object.freeze(["127.0.0.1", "localhost", "[::1]", "::1"]);

export interface CreateFetchProxyNetworkClientOptions {
  readonly fetchImpl?: typeof fetch;
}

/**
 * The shipped real client. It resolves the request URL from the (already
 * host-allowlisted) origin, requires TLS unless the origin is an explicit
 * loopback test origin, refuses redirects, and buffers at most
 * `maxResponseBytes` before failing closed.
 */
export function createFetchProxyNetworkClient(
  options: CreateFetchProxyNetworkClientOptions = {}
): ProxyNetworkClient {
  const doFetch = options.fetchImpl ?? fetch;
  return Object.freeze({
    async send(request: ProxyOutboundRequest): Promise<ProxyNetworkResponse> {
      const url = buildUrl(request);
      const controller = new AbortController();
      let dispatched = false;
      const timer = setTimeout(() => controller.abort(), request.timeoutMs);
      timer.unref?.();
      try {
        dispatched = true;
        const response = await doFetch(url, {
          method: request.method,
          headers: { ...request.headers },
          body: request.body ?? undefined,
          redirect: "manual",
          signal: controller.signal,
          // No proxy dispatcher is configured, so no HTTP(S)_PROXY / no_proxy
          // environment variable is honored by construction.
        });
        if (response.status >= 300 && response.status < 400) {
          throw new ProxyNetworkError("redirect");
        }
        const body = await readCapped(response, request.maxResponseBytes);
        return Object.freeze({ status: response.status, body });
      } catch (error) {
        if (error instanceof ProxyNetworkError) throw error;
        if (isAbortError(error)) {
          throw new ProxyNetworkError(
            dispatched ? "timeout-after-send" : "timeout-before-response"
          );
        }
        throw new ProxyNetworkError("transport");
      } finally {
        clearTimeout(timer);
      }
    },
  });
}

function buildUrl(request: ProxyOutboundRequest): URL {
  let origin: URL;
  try {
    origin = new URL(request.origin);
  } catch {
    throw new ProxyNetworkError("transport");
  }
  const isLoopback = LOOPBACK_HOSTS.includes(origin.hostname) || origin.hostname === "::1";
  if (origin.protocol !== "https:" && !(origin.protocol === "http:" && isLoopback)) {
    throw new ProxyNetworkError("tls-required");
  }
  const url = new URL(request.path, origin);
  // Reject any path that resolved outside the origin (defense in depth; the
  // proxy already validates path segments).
  if (url.origin !== origin.origin) throw new ProxyNetworkError("transport");
  for (const [key, value] of Object.entries(request.query)) {
    url.searchParams.set(key, value);
  }
  return url;
}

async function readCapped(response: Response, maxBytes: number): Promise<Buffer> {
  const stream = response.body;
  if (!stream) return Buffer.alloc(0);
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
        if (total > maxBytes) {
          await reader.cancel().catch(() => undefined);
          throw new ProxyNetworkError("response-too-large");
        }
        chunks.push(chunk);
      }
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, total);
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError");
}
