import {
  digestRuntimeCommandClaims,
  type RuntimeCommandAuthorityIssuer,
  type RuntimeCommandClaims,
} from "@/lib/runtime";

/** Deterministic structural authority for kernel/journal tests; crypto is tested separately. */
export function createTestRuntimeCommandAuthorityIssuer(): RuntimeCommandAuthorityIssuer {
  const issue = ((claims: RuntimeCommandClaims) =>
    Object.freeze({
      issuer: "team-session" as const,
      issuerKeyId: "team-session:test-key",
      audience: "runtime" as const,
      capability: claims.kind,
      claimsDigest: digestRuntimeCommandClaims(claims),
      issuedAtMs: claims.issuedAtMs,
      expiresAtMs: claims.deadlineAtMs,
      signature: "test-signature",
    })) as RuntimeCommandAuthorityIssuer["issue"];
  return Object.freeze({
    issue,
  });
}
