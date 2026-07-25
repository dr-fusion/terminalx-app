import {
  createHash,
  createPublicKey,
  createVerify,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";
import { SecretBrokerProtocolError } from "../protocol";

/**
 * Slice 8E2/8F Sign in with Slack (OIDC) identity-link completion.
 *
 * The id_token is verified entirely inside the broker: the signing key is
 * resolved from Slack's JWKS through an injectable client (keys cached with a
 * bounded TTL), and `iss`/`aud`/`exp` plus a `nonce` bound to the Link Challenge
 * digest are all checked before any identity is returned. The broker returns
 * only the verified non-secret identity for `verifySlackOidcProof`; the raw
 * id_token never crosses the socket.
 */
const DEFAULT_JWKS_TTL_MS = 10 * 60 * 1000;
const MAX_JWKS_KEYS = 16;
const MAX_ID_TOKEN_BYTES = 16 * 1024;
const CLOCK_SKEW_MS = 60 * 1000;
const SUPPORTED_ALGS = new Set(["RS256"]);

export interface SlackJsonWebKey {
  readonly kid: string;
  readonly kty: string;
  readonly alg?: string;
  readonly n: string;
  readonly e: string;
  readonly use?: string;
}

export interface SlackOidcJwksClient {
  fetchSlackOidcJwks(): Promise<{ readonly keys: readonly SlackJsonWebKey[] }>;
}

export interface VerifiedSlackOidcIdentity {
  readonly provider: "slack";
  readonly externalTenantId: string;
  readonly externalAppId: string;
  readonly externalSubject: string;
  /** The raw challenge (id_token `nonce`) whose digest equals the expectation. */
  readonly challenge: string;
  /** Single-use replay id (id_token `jti`). */
  readonly replayId: string;
}

export interface VerifySlackOidcInput {
  readonly idToken: string;
  readonly expectedIssuer: string;
  readonly expectedAudience: string;
  readonly expectedTenantId: string;
  readonly expectedAppId: string;
  /** SHA-256 of the Link Challenge; the id_token `nonce` must hash to this. */
  readonly challengeDigest: string;
}

export interface SlackOidcVerifier {
  verify(input: VerifySlackOidcInput): Promise<VerifiedSlackOidcIdentity>;
}

export interface CreateSlackOidcVerifierOptions {
  readonly jwks: SlackOidcJwksClient;
  readonly clock?: () => number;
  readonly jwksTtlMs?: number;
}

interface CachedJwks {
  readonly keys: Map<string, KeyObject>;
  readonly expiresAtMs: number;
}

export function createSlackOidcVerifier(
  options: CreateSlackOidcVerifierOptions
): SlackOidcVerifier {
  const clock = options.clock ?? Date.now;
  const ttlMs = options.jwksTtlMs ?? DEFAULT_JWKS_TTL_MS;
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 60 * 60 * 1000) {
    throw new TypeError();
  }
  let cache: CachedJwks | null = null;

  async function resolveKey(kid: string, allowRefresh: boolean): Promise<KeyObject | null> {
    const now = clock();
    if (cache && cache.expiresAtMs > now) {
      const key = cache.keys.get(kid);
      if (key || !allowRefresh) return key ?? null;
    }
    const fetched = await options.jwks.fetchSlackOidcJwks();
    cache = parseJwks(fetched, clock() + ttlMs);
    return cache.keys.get(kid) ?? null;
  }

  return Object.freeze({
    async verify(input: VerifySlackOidcInput): Promise<VerifiedSlackOidcIdentity> {
      const parsed = parseIdToken(input.idToken);
      // Refresh JWKS once if the kid is unknown (key rotation).
      let key = await resolveKey(parsed.kid, false);
      if (!key) key = await resolveKey(parsed.kid, true);
      if (!key) throw declined();
      if (!verifySignature(parsed, key)) throw declined();

      const now = clock();
      const claims = parsed.claims;
      if (
        claims.iss !== input.expectedIssuer ||
        !audienceMatches(claims.aud, input.expectedAudience) ||
        typeof claims.exp !== "number" ||
        claims.exp * 1000 + CLOCK_SKEW_MS < now ||
        (typeof claims.iat === "number" && claims.iat * 1000 - CLOCK_SKEW_MS > now)
      ) {
        throw declined();
      }
      const teamId =
        nestedString(claims, "https://slack.com/team_id") ?? stringClaim(claims.team_id);
      const subject = stringClaim(claims.sub);
      const nonce = stringClaim(claims.nonce);
      const jti = stringClaim(claims.jti) ?? nonce;
      if (
        teamId !== input.expectedTenantId ||
        !subject ||
        !nonce ||
        !jti ||
        !sameDigest(sha256(nonce), input.challengeDigest)
      ) {
        throw declined();
      }
      return Object.freeze({
        provider: "slack",
        externalTenantId: teamId,
        externalAppId: input.expectedAppId,
        externalSubject: subject,
        challenge: nonce,
        replayId: jti,
      });
    },
  });
}

interface ParsedIdToken {
  readonly kid: string;
  readonly signingInput: string;
  readonly signature: Buffer;
  readonly claims: Record<string, unknown>;
}

function parseIdToken(idToken: unknown): ParsedIdToken {
  if (typeof idToken !== "string" || Buffer.byteLength(idToken, "utf8") > MAX_ID_TOKEN_BYTES) {
    throw declined();
  }
  const parts = idToken.split(".");
  if (parts.length !== 3) throw declined();
  const [headerPart, payloadPart, signaturePart] = parts;
  if (!headerPart || !payloadPart || !signaturePart) throw declined();
  const header = decodeJson(headerPart);
  const claims = decodeJson(payloadPart);
  const alg = header.alg;
  const kid = header.kid;
  if (
    typeof alg !== "string" ||
    !SUPPORTED_ALGS.has(alg) ||
    typeof kid !== "string" ||
    kid.length === 0
  ) {
    throw declined();
  }
  return {
    kid,
    signingInput: `${headerPart}.${payloadPart}`,
    signature: Buffer.from(signaturePart, "base64url"),
    claims,
  };
}

function verifySignature(parsed: ParsedIdToken, key: KeyObject): boolean {
  try {
    const verifier = createVerify("RSA-SHA256");
    verifier.update(parsed.signingInput, "utf8");
    verifier.end();
    return verifier.verify(key, parsed.signature);
  } catch {
    return false;
  }
}

function parseJwks(
  value: { readonly keys?: readonly SlackJsonWebKey[] },
  expiresAtMs: number
): CachedJwks {
  if (typeof value !== "object" || value === null || !Array.isArray(value.keys)) {
    throw new SecretBrokerProtocolError("unavailable");
  }
  if (value.keys.length === 0 || value.keys.length > MAX_JWKS_KEYS) {
    throw new SecretBrokerProtocolError("unavailable");
  }
  const keys = new Map<string, KeyObject>();
  for (const jwk of value.keys) {
    if (
      typeof jwk !== "object" ||
      jwk === null ||
      jwk.kty !== "RSA" ||
      typeof jwk.kid !== "string" ||
      typeof jwk.n !== "string" ||
      typeof jwk.e !== "string" ||
      (jwk.alg !== undefined && jwk.alg !== "RS256")
    ) {
      continue;
    }
    try {
      const key = createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" });
      keys.set(jwk.kid, key);
    } catch {
      // Skip malformed keys; a usable kid must remain.
    }
  }
  if (keys.size === 0) throw new SecretBrokerProtocolError("unavailable");
  return { keys, expiresAtMs };
}

function decodeJson(part: string): Record<string, unknown> {
  let text: string;
  try {
    text = Buffer.from(part, "base64url").toString("utf8");
  } catch {
    throw declined();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw declined();
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw declined();
  return parsed as Record<string, unknown>;
}

function audienceMatches(aud: unknown, expected: string): boolean {
  if (typeof aud === "string") return aud === expected;
  if (Array.isArray(aud)) return aud.length === 1 && aud[0] === expected;
  return false;
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function nestedString(claims: Record<string, unknown>, key: string): string | undefined {
  return stringClaim(claims[key]);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sameDigest(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function declined(): SecretBrokerProtocolError {
  return new SecretBrokerProtocolError("permission-denied");
}
