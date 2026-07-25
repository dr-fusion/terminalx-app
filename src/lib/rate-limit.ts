import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { trustProxyHeaders } from "./security-config";

const WINDOW_MS = 60_000;
const MAX_ATTEMPTS = 5;
const MAX_KEYS = 10_000;
const PAIRING_SOURCE_MAX_ATTEMPTS = 300;
const PAIRING_GLOBAL_MAX_ATTEMPTS = 6_000;
const DIRECT_PEER_HEADER = "x-terminalx-direct-peer-v1";
const DIRECT_PEER_DOMAIN = "terminalx-direct-peer-v1\0";
const DIRECT_PEER_REGISTRY_KEY = Symbol.for("terminalx.direct-peer-authority.v1");

interface DirectPeerAuthorityRegistry {
  secret: Buffer | null;
}

function directPeerAuthorityRegistry(): DirectPeerAuthorityRegistry {
  const shared = globalThis as typeof globalThis & Record<symbol, unknown>;
  const existing = shared[DIRECT_PEER_REGISTRY_KEY];
  if (existing) return existing as DirectPeerAuthorityRegistry;
  const created: DirectPeerAuthorityRegistry = { secret: null };
  shared[DIRECT_PEER_REGISTRY_KEY] = created;
  return created;
}

function normalizePeerAddress(value: string | undefined | null): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 128 ||
    /[\u0000-\u0020\u007f]/.test(normalized) ||
    isIP(normalized) === 0
  ) {
    return null;
  }
  return normalized;
}

function directPeerSignature(secret: Buffer, encodedPeer: string): Buffer {
  return createHmac("sha256", secret)
    .update(DIRECT_PEER_DOMAIN, "utf8")
    .update(encodedPeer, "ascii")
    .digest();
}

/**
 * Overwrite the private peer header at the custom-server ingress boundary.
 * Next route handlers do not receive Node's socket, so an in-process random
 * HMAC key lets a separately bundled route distinguish this server-authored
 * value from an attacker-supplied request header. Deployments using `next
 * start` never initialize the key and therefore ignore the header.
 */
export function stampAuthoritativeDirectPeer(request: {
  headers: Record<string, string | string[] | undefined>;
  socket: { remoteAddress?: string };
}): void {
  delete request.headers[DIRECT_PEER_HEADER];
  const peer = normalizePeerAddress(request.socket.remoteAddress);
  if (!peer) return;

  const registry = directPeerAuthorityRegistry();
  registry.secret ??= randomBytes(32);
  const encodedPeer = Buffer.from(peer, "utf8").toString("base64url");
  const signature = directPeerSignature(registry.secret, encodedPeer).toString("base64url");
  request.headers[DIRECT_PEER_HEADER] = `${encodedPeer}.${signature}`;
}

function verifiedDirectPeer(headers: { get(name: string): string | null }): string | null {
  const secret = directPeerAuthorityRegistry().secret;
  if (!secret) return null;
  const value = headers.get(DIRECT_PEER_HEADER);
  if (!value || value.length > 512) return null;
  const parts = value.split(".");
  if (
    parts.length !== 2 ||
    !parts[0] ||
    !parts[1] ||
    !/^[A-Za-z0-9_-]+$/.test(parts[0]) ||
    !/^[A-Za-z0-9_-]+$/.test(parts[1])
  ) {
    return null;
  }

  try {
    const supplied = Buffer.from(parts[1], "base64url");
    if (supplied.toString("base64url") !== parts[1]) return null;
    const expected = directPeerSignature(secret, parts[0]);
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return null;
    const decoded = Buffer.from(parts[0], "base64url");
    if (decoded.toString("base64url") !== parts[0]) return null;
    const peer = normalizePeerAddress(decoded.toString("utf8"));
    return peer && Buffer.from(peer, "utf8").equals(decoded) ? peer : null;
  } catch {
    return null;
  }
}

const buckets = new Map<string, number[]>();
const pairingPeerBuckets = new Map<string, number[]>();
let unattributedPairingAttempts: number[] = [];
let globalPairingAttempts: number[] = [];

export function isRateLimited(key: string): boolean {
  const now = Date.now();
  const attempts = buckets.get(key) ?? [];
  const recent = attempts.filter((t) => now - t < WINDOW_MS);

  if (recent.length >= MAX_ATTEMPTS) {
    buckets.set(key, recent);
    return true;
  }

  if (!buckets.has(key) && buckets.size >= MAX_KEYS) {
    const oldest = buckets.keys().next().value;
    if (oldest !== undefined) buckets.delete(oldest);
  }

  recent.push(now);
  buckets.set(key, recent);
  return false;
}

/**
 * High-volume resource guard for pairing redemption. This state is isolated
 * from the attacker-cardinality per-code limiter, so unique code guesses
 * cannot evict and reset a peer's aggregate ceiling. The unattributed and
 * process-global buckets are fixed entries rather than attacker-selected map
 * keys. The low five-attempt replay bucket remains code-specific in the route.
 */
export function isPairingSourceRateLimited(peer: string): boolean {
  const now = Date.now();
  const globalRecent = globalPairingAttempts.filter((time) => now - time < WINDOW_MS);
  const peerKey =
    peer === "unknown"
      ? null
      : createHash("sha256")
          .update("terminalx:pairing-peer:v1\0", "utf8")
          .update(peer, "utf8")
          .digest("hex");
  const sourceRecent = (
    peerKey ? (pairingPeerBuckets.get(peerKey) ?? []) : unattributedPairingAttempts
  ).filter((time) => now - time < WINDOW_MS);

  if (
    sourceRecent.length >= PAIRING_SOURCE_MAX_ATTEMPTS ||
    globalRecent.length >= PAIRING_GLOBAL_MAX_ATTEMPTS
  ) {
    if (peerKey) pairingPeerBuckets.set(peerKey, sourceRecent);
    else unattributedPairingAttempts = sourceRecent;
    globalPairingAttempts = globalRecent;
    return true;
  }

  if (peerKey && !pairingPeerBuckets.has(peerKey) && pairingPeerBuckets.size >= MAX_KEYS) {
    const oldest = pairingPeerBuckets.keys().next().value;
    if (oldest !== undefined) pairingPeerBuckets.delete(oldest);
  }
  sourceRecent.push(now);
  globalRecent.push(now);
  if (peerKey) pairingPeerBuckets.set(peerKey, sourceRecent);
  else unattributedPairingAttempts = sourceRecent;
  globalPairingAttempts = globalRecent;
  return false;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, attempts] of buckets) {
    const recent = attempts.filter((t) => now - t < WINDOW_MS);
    if (recent.length === 0) buckets.delete(key);
    else buckets.set(key, recent);
  }
  for (const [key, attempts] of pairingPeerBuckets) {
    const recent = attempts.filter((time) => now - time < WINDOW_MS);
    if (recent.length === 0) pairingPeerBuckets.delete(key);
    else pairingPeerBuckets.set(key, recent);
  }
  unattributedPairingAttempts = unattributedPairingAttempts.filter(
    (time) => now - time < WINDOW_MS
  );
  globalPairingAttempts = globalPairingAttempts.filter((time) => now - time < WINDOW_MS);
}, 300_000).unref?.();

export function clientIp(req: { headers: { get(name: string): string | null } }): string {
  if (trustProxyHeaders()) {
    const fwd = req.headers.get("x-forwarded-for");
    const forwardedPeer = normalizePeerAddress(fwd?.split(",")[0]);
    if (forwardedPeer) return forwardedPeer;
    const real = req.headers.get("x-real-ip");
    const realPeer = normalizePeerAddress(real);
    if (realPeer) return realPeer;
  }
  return verifiedDirectPeer(req.headers) ?? "unknown";
}
