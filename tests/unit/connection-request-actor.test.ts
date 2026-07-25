import { describe, expect, it } from "vitest";
import { connectionActorSnapshot } from "@/lib/connections/request-actor";

describe("connection actor snapshot", () => {
  it("fails closed for auth-disabled and legacy actors", () => {
    expect(
      connectionActorSnapshot({
        kind: "human",
        userId: "single-user",
        username: "admin",
        displayName: "admin",
        legacyRole: "admin",
      })
    ).toBeNull();
  });

  it("copies only the verified canonical and credential fences", () => {
    expect(
      connectionActorSnapshot({
        kind: "human",
        userId: "user-1",
        username: "alice",
        displayName: "Alice",
        legacyRole: "admin",
        authentication: {
          provider: "local",
          subject: "alice",
          userGeneration: 2,
          identityGeneration: 3,
          authenticatedAtMs: 1_000,
          credentialIssuedAtMs: 1_100,
          credentialExpiresAtMs: 2_000,
          credentialJtiDigest: "a".repeat(64),
          device: { provenance: "paired-device", id: "device-1" },
        },
      })
    ).toEqual({
      userId: "user-1",
      userGeneration: 2,
      authProvider: "local",
      authSubject: "alice",
      authIdentityGeneration: 3,
      authenticatedAtMs: 1_000,
      credentialIssuedAtMs: 1_100,
      credentialExpiresAtMs: 2_000,
      credentialJtiDigest: "a".repeat(64),
      device: { provenance: "paired-device", id: "device-1" },
    });
  });
});
