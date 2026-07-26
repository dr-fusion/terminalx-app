/**
 * Redaction guard for every operations surface (telemetry, metrics labels,
 * audit context, backup manifests). It enforces the digest-only discipline: no
 * secret material, token, credential value, cookie, or raw provider body may
 * reach a log/metric/backup artifact. It redacts by field name (any field whose
 * key names a secret is dropped wholesale) and by value shape (bearer tokens and
 * JWTs embedded in free text are scrubbed). SHA-256 hex digests are intentionally
 * preserved — they are the safe, non-reversible form we deliberately record.
 */

export const REDACTED = "[redacted]";

const SECRET_KEY_PATTERN =
  /(secret|token|passwd|password|passphrase|authorization|cookie|credential|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key|session[_-]?token|refresh[_-]?token|id[_-]?token|bearer|webhook[_-]?secret|jwt|otp|passcode)/i;

// A three-segment base64url JWT anywhere in free text.
const JWT_PATTERN = /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
// `Bearer <token>` / `Basic <token>` authorization values in free text.
const AUTH_SCHEME_PATTERN = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi;

const MAX_DEPTH = 8;
const MAX_STRING_LENGTH = 4096;

/** True when a field key names secret material and must be dropped wholesale. */
export function isSecretKey(key: string): boolean {
  return SECRET_KEY_PATTERN.test(key);
}

/** Scrub bearer/basic authorization values and embedded JWTs from free text. */
export function redactString(value: string): string {
  const bounded =
    value.length > MAX_STRING_LENGTH ? `${value.slice(0, MAX_STRING_LENGTH)}…` : value;
  return bounded
    .replace(AUTH_SCHEME_PATTERN, "$1 [redacted]")
    .replace(JWT_PATTERN, "[redacted-jwt]");
}

/**
 * Recursively redact an arbitrary value for safe emission. Objects are cloned;
 * secret-named keys are replaced with {@link REDACTED}; strings are value-scrubbed;
 * depth and breadth are bounded so a hostile structure cannot exhaust the logger.
 */
export function redactValue(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactString(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (depth >= MAX_DEPTH) return "[truncated]";
  if (Array.isArray(value)) {
    return value.slice(0, 256).map((entry) => redactValue(entry, depth + 1));
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      out[key] = isSecretKey(key) ? REDACTED : redactValue(entry, depth + 1);
    }
    return out;
  }
  // Functions, symbols, and other non-serializable values never leak their body.
  return "[unserializable]";
}

/** Redact a flat set of structured log fields. */
export function redactFields(fields: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(fields)) {
    out[key] = isSecretKey(key) ? REDACTED : redactValue(value, 1);
  }
  return out;
}
