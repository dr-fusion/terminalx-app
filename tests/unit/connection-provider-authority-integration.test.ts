import type Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import {
  createConnectionAuthority,
  type ConnectionAuthority,
  type CredentialHandleRegistrationExpectation,
  type VerifiedCredentialHandleRegistration,
} from "@/lib/connections/authority";
import { canonicalStringSet, type ConnectionActorSnapshot } from "@/lib/connections/contracts";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { verifyTelegramDeepLinkProof } from "@/lib/connections/providers/telegram-adapter";
import {
  TELEGRAM_IDENTITY_LINK_SCOPES,
  TELEGRAM_INSTALLATION_REVIEWED_SCOPES,
  TELEGRAM_INSTALLATION_CAPABILITIES,
} from "@/lib/connections/providers/scopes";

describe("provider adapter linking through the connection authority", () => {
  let database: TeamSessionDatabase | undefined;
  afterEach(() => {
    database?.close();
    database = undefined;
  });

  function harness() {
    const db = openTeamSessionDatabase({ filename: ":memory:" });
    database = db;
    seed(db.db);
    const now = 1_000_000;
    let idCounter = 0;
    let handleSequence = 0;
    let byteCounter = 0;
    const registrations = new WeakMap<object, VerifiedCredentialHandleRegistration>();
    const brokerProof = (expectation: CredentialHandleRegistrationExpectation): object => {
      const sequence = ++handleSequence;
      const proof = Object.freeze({ kind: "broker", sequence });
      registrations.set(proof, {
        ...expectation,
        handleId: `txch_v1_${sequence.toString(16).padStart(64, "0")}`,
        receiptId: `receipt-${sequence}`,
      });
      return proof;
    };
    const authority: ConnectionAuthority = createConnectionAuthority({
      db: db.db,
      clock: () => now,
      idGenerator: () => `gen-${++idCounter}`,
      randomBytes: (size) => Buffer.alloc(size, ++byteCounter),
      verifyCredentialHandleRegistration: ({ proof }) =>
        typeof proof === "object" && proof !== null ? (registrations.get(proof) ?? null) : null,
      verifyProviderProof: verifyTelegramDeepLinkProof,
      validateAuthenticationSnapshot: () => true,
    });
    const actor: ConnectionActorSnapshot = {
      userId: "user-1",
      userGeneration: 1,
      authProvider: "local",
      authSubject: "alice",
      authIdentityGeneration: 1,
      authenticatedAtMs: 999_000,
      credentialIssuedAtMs: 999_000,
      credentialExpiresAtMs: 999_000 + 86_400_000,
      credentialJtiDigest: "a".repeat(64),
      device: { provenance: "browser" },
    };
    const installation = authority.createChannelInstallation({
      actor,
      teamId: "team-1",
      provider: "telegram",
      externalTenantId: "998877",
      externalAppId: "998877",
      expectedBrokerKind: "oauth-envelope",
      credentialBrokerProof: brokerProof({
        provider: "telegram",
        brokerKind: "oauth-envelope",
        usage: "installation",
        authorityBinding: {
          kind: "installation",
          teamId: "team-1",
          externalTenantId: "998877",
          externalAppId: "998877",
        },
        replaces: null,
      }),
      reviewedScopes: TELEGRAM_INSTALLATION_REVIEWED_SCOPES,
      capabilities: TELEGRAM_INSTALLATION_CAPABILITIES,
    });
    return { authority, actor, installation };
  }

  function deepLink(challenge: string, overrides: Record<string, unknown> = {}) {
    return {
      kind: "telegram-deeplink",
      externalTenantId: "998877",
      externalAppId: "998877",
      externalSubject: "555",
      challenge,
      replayId: "42",
      ...overrides,
    };
  }

  it("links a Telegram identity via a verified deep-link proof, then fences replay", () => {
    const { authority, actor, installation } = harness();
    const issued = authority.issueLinkChallenge({
      actor,
      installationId: installation.id,
      expectedInstallationRevision: installation.revision,
      requestedScopes: TELEGRAM_IDENTITY_LINK_SCOPES,
    });
    const connection = authority.completeLinkChallenge({
      challenge: issued.challenge,
      providerProof: deepLink(issued.challenge),
    });
    expect(connection).toMatchObject({
      userId: "user-1",
      provider: "telegram",
      externalSubject: "555",
      status: "active",
      scopes: [...TELEGRAM_IDENTITY_LINK_SCOPES],
    });
    // Replaying the same single-use challenge fails closed.
    expect(() =>
      authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: deepLink(issued.challenge, { replayId: "43" }),
      })
    ).toThrow(/already used/);
  });

  it("rejects a wrong-installation deep-link binding", () => {
    const { authority, actor, installation } = harness();
    const issued = authority.issueLinkChallenge({
      actor,
      installationId: installation.id,
      expectedInstallationRevision: installation.revision,
      requestedScopes: TELEGRAM_IDENTITY_LINK_SCOPES,
    });
    expect(() =>
      authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: deepLink(issued.challenge, { externalTenantId: "111111" }),
      })
    ).toThrow(/invalid or misbound/);
  });

  it("enforces that requested scopes are a reviewed subset", () => {
    const { authority, actor, installation } = harness();
    expect(() =>
      authority.issueLinkChallenge({
        actor,
        installationId: installation.id,
        expectedInstallationRevision: installation.revision,
        requestedScopes: ["not:reviewed"],
      })
    ).toThrow(/was not reviewed/);
  });

  it("rejects a proof whose challenge digest does not match", () => {
    const { authority, actor, installation } = harness();
    const issued = authority.issueLinkChallenge({
      actor,
      installationId: installation.id,
      expectedInstallationRevision: installation.revision,
      requestedScopes: TELEGRAM_IDENTITY_LINK_SCOPES,
    });
    expect(() =>
      authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: deepLink(issued.challenge + "tampered"),
      })
    ).toThrow(/invalid or misbound/);
    // canonicalStringSet is available for parity with contracts helpers.
    expect(canonicalStringSet(TELEGRAM_IDENTITY_LINK_SCOPES, "x").values).toEqual([
      ...TELEGRAM_IDENTITY_LINK_SCOPES,
    ]);
  });
});

function seed(db: Database.Database): void {
  db.exec(`
    INSERT INTO users (
      id, username, display_name, legacy_role, status, generation,
      created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
    ) VALUES ('user-1', 'alice', 'Alice', 'admin', 'active', 1, 100, 100, 100, NULL);
    INSERT INTO auth_identities (
      id, user_id, provider, subject, status, generation,
      created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
    ) VALUES ('identity-1', 'user-1', 'local', 'alice', 'active', 1, 100, 100, 100, NULL);
    INSERT INTO teams (id, name, created_at_ms) VALUES ('team-1', 'Team', 100);
    INSERT INTO team_memberships (
      team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
    ) VALUES ('team-1', 'user-1', 'owner', 'active', 1, 100, NULL);
  `);
}
