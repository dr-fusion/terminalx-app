export interface HeaderBag {
  get(name: string): string | null;
}

export interface RequestUrlLike {
  protocol: string;
  host: string;
}

export interface RequestLike {
  headers: HeaderBag;
  nextUrl: RequestUrlLike;
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function isReadOnlyMode(): boolean {
  return process.env.TERMINUS_READ_ONLY === "true";
}

export function getConfiguredMaxSessions(): number {
  return parsePositiveInt(process.env.TERMINUS_MAX_SESSIONS, 20);
}

export function getTelegramMaxTopics(): number {
  return parsePositiveInt(process.env.TERMINALX_TELEGRAM_MAX_TOPICS, Number.POSITIVE_INFINITY);
}

export function getPublicUrl(): string | null {
  const raw = process.env.TERMINALX_PUBLIC_URL?.trim();
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    parsed.pathname = parsed.pathname.replace(/\/+$/, "");
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}

export function trustProxyHeaders(): boolean {
  return process.env.TERMINALX_TRUST_PROXY_HEADERS === "true";
}

export function externalBaseUrl(req: RequestLike): string {
  const publicUrl = getPublicUrl();
  if (publicUrl) return publicUrl;

  const useForwarded = trustProxyHeaders();
  const proto =
    (useForwarded && req.headers.get("x-forwarded-proto")) || req.nextUrl.protocol.replace(":", "");
  const host =
    (useForwarded && req.headers.get("x-forwarded-host")) ||
    req.headers.get("host") ||
    req.nextUrl.host;

  return `${proto}://${host}`;
}

export function isSecureRequest(req: RequestLike): boolean {
  try {
    return new URL(externalBaseUrl(req)).protocol === "https:";
  } catch {
    return req.nextUrl.protocol === "https:";
  }
}

export function allowsNoAuthOnPublicHost(): boolean {
  return process.env.TERMINALX_ALLOW_NO_AUTH === "1";
}

export function isLoopbackHost(host: string): boolean {
  const normalized = host
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, "");
  return (
    normalized === "localhost" ||
    normalized === "::1" ||
    normalized === "0:0:0:0:0:0:0:1" ||
    normalized.startsWith("127.")
  );
}

export function shouldRefuseNoAuth(authMode: string, bindHost: string): boolean {
  return authMode === "none" && !allowsNoAuthOnPublicHost() && !isLoopbackHost(bindHost);
}
