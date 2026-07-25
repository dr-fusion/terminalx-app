import type Database from "better-sqlite3";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createConnectionAuthority,
  providerProofReplayDigest,
  type ConnectionAuthority,
  type CreateConnectionAuthorityOptions,
  type CredentialHandleAuthorityBinding,
  type CredentialHandleRegistrationExpectation,
  type ProviderProofExpectation,
  type VerifiedCredentialHandleRegistration,
} from "@/lib/connections/authority";
import {
  canonicalStringSet,
  sha256 as sha256ForTest,
  type ConnectionActorSnapshot,
} from "@/lib/connections/contracts";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import {
  createTeamSessions,
  TEAM_SESSION_SCHEMA_VERSION,
  type SessionCommand,
} from "@/lib/team-sessions";

describe("connection authority", () => {
  let database: TeamSessionDatabase | undefined;

  afterEach(() => {
    database?.close();
    database = undefined;
  });

  it("links a provider identity through a digest-only, single-use challenge", () => {
    const harness = createHarness();
    database = harness.database;
    const { authority, actor } = harness;
    const installation = createInstallation(harness);
    const beforeMemberships = count(database.db, "team_memberships");
    const beforeParticipants = count(database.db, "session_participants");
    const beforeResponsibilities = count(database.db, "session_responsibilities");

    const issued = authority.issueLinkChallenge({
      actor,
      installationId: installation.id,
      expectedInstallationRevision: installation.revision,
      requestedScopes: ["chat:write"],
    });
    const stored = database.db
      .prepare("SELECT challenge_digest, status FROM link_challenges")
      .get() as { challenge_digest: string; status: string };
    expect(stored).toMatchObject({ status: "active" });
    expect(stored.challenge_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(stored.challenge_digest).not.toBe(issued.challenge);
    expect(
      JSON.stringify(database.db.prepare("SELECT * FROM link_challenges").all())
    ).not.toContain(issued.challenge);

    const connection = authority.completeLinkChallenge({
      challenge: issued.challenge,
      providerProof: harness.providerProof(),
    });
    expect(connection).toMatchObject({
      userId: "user-1",
      provider: "slack",
      externalTenantId: "tenant-1",
      externalSubject: "external-user-1",
      status: "active",
      generation: 1,
      scopes: ["chat:write"],
    });
    expect(() =>
      authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: harness.providerProof(),
      })
    ).toThrow("already used");
    expect(count(database.db, "team_memberships")).toBe(beforeMemberships);
    expect(count(database.db, "session_participants")).toBe(beforeParticipants);
    expect(count(database.db, "session_responsibilities")).toBe(beforeResponsibilities);
    expect(
      database.db
        .prepare(
          `SELECT event_type FROM connection_authority_ledger
           WHERE event_type NOT LIKE '%.mutation-recorded' ORDER BY sequence`
        )
        .all()
    ).toEqual([
      { event_type: "credential-handle.registered" },
      { event_type: "channel-installation.created" },
      { event_type: "link-challenge.issued" },
      { event_type: "link-challenge.consumed" },
      { event_type: "identity-connection.created" },
    ]);
    expect(
      database.db
        .prepare(
          `SELECT COUNT(*) AS count FROM connection_authority_ledger
           WHERE event_type LIKE '%.mutation-recorded'`
        )
        .get()
    ).toEqual({ count: 5 });
  });

  it("requires recent primary authentication and exact membership at completion", () => {
    const harness = createHarness();
    database = harness.database;
    const { authority, actor } = harness;
    const installation = createInstallation(harness);

    expect(() =>
      authority.issueLinkChallenge({
        actor: { ...actor, authenticatedAtMs: undefined },
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      })
    ).toThrow("Recent primary authentication");
    expect(() =>
      authority.issueLinkChallenge({
        actor: { ...actor, authenticatedAtMs: 699_999 },
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      })
    ).toThrow("Recent primary authentication");

    const issued = authority.issueLinkChallenge({
      actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    database.db
      .prepare("UPDATE team_memberships SET version = 2 WHERE team_id = ? AND user_id = ?")
      .run("team-1", "user-1");
    expect(() =>
      authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: harness.providerProof(),
      })
    ).toThrow("membership changed");
    expect(database.db.prepare("SELECT status, version FROM link_challenges").get()).toEqual({
      status: "active",
      version: 1,
    });
  });

  it("never lets a Link Challenge outlive the source credential", () => {
    const harness = createHarness();
    database = harness.database;
    const installation = createInstallation(harness);

    expect(() =>
      harness.authority.issueLinkChallenge({
        actor: { ...harness.actor, credentialExpiresAtMs: 1_059_999 },
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      })
    ).toThrow("Source credential expires too soon");

    const issued = harness.authority.issueLinkChallenge({
      actor: { ...harness.actor, credentialExpiresAtMs: 1_090_000 },
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    expect(issued.expiresAtMs).toBe(1_090_000);
    expect(
      database.db
        .prepare(
          `SELECT auth_session_expires_at_ms, expires_at_ms
           FROM link_challenges WHERE challenge_digest = ?`
        )
        .get(sha256ForTest(issued.challenge))
    ).toEqual({ auth_session_expires_at_ms: 1_090_000, expires_at_ms: 1_090_000 });

    harness.setNow(1_090_000);
    expect(() =>
      harness.authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: harness.providerProof(),
      })
    ).toThrow("Link Challenge expired");
  });

  it("rechecks expiry after provider proof verification before any durable mutation", () => {
    const boundary = { advance: () => {} };
    const harness = createHarness({
      verifyProviderProof: ({ expected }) => {
        boundary.advance();
        const grantedScopes = canonicalStringSet(expected.requestedScopes, "test granted scopes");
        return {
          ...expected,
          externalSubject: "external-user-1",
          proofReplayId: "provider-advanced-clock",
          grantedScopes: grantedScopes.values,
          grantedScopesDigest: grantedScopes.digest,
        };
      },
    });
    boundary.advance = () => harness.setNow(1_600_000);
    database = harness.database;
    const installation = createInstallation(harness);
    const issued = harness.authority.issueLinkChallenge({
      actor: harness.actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });

    expect(() =>
      harness.authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: { kind: "provider-proof-that-blocked" },
      })
    ).toThrow("Link Challenge expired");
    expect(database.db.prepare("SELECT status, version FROM link_challenges").get()).toEqual({
      status: "active",
      version: 1,
    });
    expect(count(database.db, "identity_connections")).toBe(0);
  });

  it("rolls back broker effects when the source expires during broker verification", () => {
    const boundary = { advance: () => {} };
    let registrationSequence = 0;
    const harness = createHarness({
      verifyCredentialHandleRegistration: ({ expected }) => {
        registrationSequence += 1;
        if (expected.usage === "identity-connection") boundary.advance();
        return {
          ...expected,
          handleId: `txch_v1_${registrationSequence.toString(16).padStart(64, "0")}`,
          receiptId: `clock-advancing-broker-${registrationSequence}`,
        };
      },
    });
    boundary.advance = () => harness.setNow(1_600_000);
    database = harness.database;
    const installation = createInstallation(harness);
    const replayId = "broker-advanced-clock-provider-proof";
    const issued = harness.authority.issueLinkChallenge({
      actor: harness.actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    const providerProofDigest = providerProofReplayDigest({
      provider: "slack",
      externalTenantId: "tenant-1",
      externalAppId: "app-1",
      proofReplayId: replayId,
    });
    const identityExpectation: CredentialHandleRegistrationExpectation = {
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "identity-connection",
      authorityBinding: {
        kind: "identity-connection",
        userId: "user-1",
        installationId: installation.id,
        installationRevision: 1,
        externalTenantId: "tenant-1",
        externalSubject: "external-user-1",
        providerProofReplayDigest: providerProofDigest,
      },
      replaces: null,
    };

    expect(() =>
      harness.authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: harness.providerProof({ replayId }),
        identityCredential: {
          expectedBrokerKind: "oauth-envelope",
          brokerProof: harness.brokerProof(identityExpectation),
        },
      })
    ).toThrow("Link Challenge expired");
    expect(database.db.prepare("SELECT status, version FROM link_challenges").get()).toEqual({
      status: "active",
      version: 1,
    });
    expect(count(database.db, "credential_handles")).toBe(1);
    expect(count(database.db, "identity_connections")).toBe(0);
  });

  it("never silently transfers historical external attribution to another User", () => {
    const harness = createHarness({ includeMember: true });
    database = harness.database;
    const { authority, actor, memberActor } = harness;
    const installation = createInstallation(harness);
    const firstChallenge = authority.issueLinkChallenge({
      actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    const firstConnection = authority.completeLinkChallenge({
      challenge: firstChallenge.challenge,
      providerProof: harness.providerProof(),
    });
    authority.revokeIdentityConnection({
      actor,
      connectionId: firstConnection.id,
      expectedGeneration: 1,
    });

    const secondChallenge = authority.issueLinkChallenge({
      actor: memberActor!,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    expect(() =>
      authority.completeLinkChallenge({
        challenge: secondChallenge.challenge,
        providerProof: harness.providerProof(),
      })
    ).toThrow("cannot be transferred");
    expect(
      database.db
        .prepare("SELECT status, version FROM link_challenges WHERE user_id = 'user-2'")
        .get()
    ).toEqual({ status: "active", version: 1 });
  });

  it("links one external identity independently to two exact Team installations", () => {
    const harness = createHarness({ includeMember: true });
    database = harness.database;
    database.db.exec(`
      INSERT INTO teams (id, name, created_at_ms) VALUES ('team-2', 'Second Team', 100);
      INSERT INTO team_memberships (
        team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
      ) VALUES ('team-2', 'user-1', 'owner', 'active', 1, 100, NULL);
      INSERT INTO team_memberships (
        team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
      ) VALUES ('team-2', 'user-2', 'member', 'active', 1, 100, NULL);
    `);
    const firstInstallation = createInstallation(harness);
    const secondExpectation: CredentialHandleRegistrationExpectation = {
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "installation",
      authorityBinding: {
        kind: "installation",
        teamId: "team-2",
        externalTenantId: "tenant-1",
        externalAppId: "app-1",
      },
      replaces: null,
    };
    const secondInstallation = harness.authority.createChannelInstallation({
      actor: harness.actor,
      teamId: "team-2",
      provider: "slack",
      externalTenantId: "tenant-1",
      externalAppId: "app-1",
      expectedBrokerKind: "oauth-envelope",
      credentialBrokerProof: harness.brokerProof(secondExpectation),
      reviewedScopes: ["chat:write"],
      capabilities: ["messages:write"],
    });

    const linkFor = (
      installation: typeof firstInstallation,
      actor: ConnectionActorSnapshot,
      replayId: string
    ) => {
      const issued = harness.authority.issueLinkChallenge({
        actor,
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      });
      return harness.authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: harness.providerProof({ replayId }),
      }).id;
    };
    const firstConnectionId = linkFor(firstInstallation, harness.actor, "multi-team-proof-1");

    const transferAttempt = harness.authority.issueLinkChallenge({
      actor: harness.memberActor!,
      installationId: secondInstallation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    expect(() =>
      harness.authority.completeLinkChallenge({
        challenge: transferAttempt.challenge,
        providerProof: harness.providerProof({ replayId: "multi-team-transfer-proof" }),
      })
    ).toThrow("cannot be transferred");
    expect(
      database.db
        .prepare(
          `SELECT status, version FROM link_challenges
           WHERE user_id = 'user-2' AND installation_id = ?`
        )
        .get(secondInstallation.id)
    ).toEqual({ status: "active", version: 1 });

    const secondConnectionId = linkFor(secondInstallation, harness.actor, "multi-team-proof-2");

    expect(
      database.db
        .prepare(
          `SELECT id, installation_id, user_id, status
           FROM identity_connections ORDER BY installation_id`
        )
        .all()
    ).toEqual([
      {
        id: firstConnectionId,
        installation_id: firstInstallation.id,
        user_id: "user-1",
        status: "active",
      },
      {
        id: secondConnectionId,
        installation_id: secondInstallation.id,
        user_id: "user-1",
        status: "active",
      },
    ]);
  });

  it("limits Channel Binding mutation to Team owners and admins", () => {
    const harness = createHarness({ includeMember: true, includeSession: true });
    database = harness.database;
    const { authority, actor, memberActor } = harness;
    const installation = createInstallation(harness);
    const input = {
      sessionId: "session-1",
      installationId: installation.id,
      expectedInstallationRevision: 1,
      conversationKind: "thread" as const,
      externalConversationId: "channel-1",
      externalThreadId: "thread-1",
      inboundPolicy: { mode: "comments-only" as const, requireLinkedIdentity: true },
      outboundPolicy: { mode: "mentions" as const, allowArtifacts: false },
    };

    expect(() => authority.createChannelBinding({ ...input, actor: memberActor! })).toThrow(
      "owner or admin"
    );
    const binding = authority.createChannelBinding({ ...input, actor });
    expect(binding).toMatchObject({ status: "active", revision: 1, provider: "slack" });
    const updated = authority.updateChannelBinding({
      actor,
      bindingId: binding.id,
      expectedRevision: 1,
      expectedInstallationRevision: 1,
      inboundPolicy: { mode: "comments-and-directives", requireLinkedIdentity: true },
      outboundPolicy: { mode: "disabled", allowArtifacts: false },
    });
    expect(updated).toMatchObject({ revision: 2, status: "active" });
    database.db.prepare("UPDATE sessions SET status = 'ended' WHERE id = 'session-1'").run();
    expect(() =>
      authority.updateChannelBinding({
        actor,
        bindingId: binding.id,
        expectedRevision: 2,
        expectedInstallationRevision: 1,
        inboundPolicy: { mode: "comments-only", requireLinkedIdentity: true },
        outboundPolicy: { mode: "mentions", allowArtifacts: false },
      })
    ).toThrow("Active Team Session");
    const revoked = authority.revokeChannelBinding({
      actor,
      bindingId: binding.id,
      expectedRevision: 2,
    });
    expect(revoked).toMatchObject({ revision: 3, status: "revoked" });
    expect(() =>
      authority.revokeChannelBinding({ actor, bindingId: binding.id, expectedRevision: 2 })
    ).toThrow("fenced");
  });

  it("rotates and revokes installation credentials atomically", () => {
    const harness = createHarness();
    database = harness.database;
    const { authority, actor, setNow } = harness;
    const installation = createInstallation(harness);
    const issued = authority.issueLinkChallenge({
      actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    const oldHandleId = installation.credentialHandleId;
    const rotated = authority.rotateChannelInstallationCredential({
      actor,
      installationId: installation.id,
      expectedRevision: 1,
      expectedHandleGeneration: 1,
      brokerProof: harness.brokerProof({
        provider: "slack",
        brokerKind: "oauth-envelope",
        usage: "installation",
        authorityBinding: {
          kind: "installation",
          teamId: "team-1",
          externalTenantId: "tenant-1",
          externalAppId: "app-1",
        },
        replaces: { handleId: oldHandleId, generation: 2 },
      }),
    });
    expect(rotated).toMatchObject({ revision: 2, credentialHandleGeneration: 1 });
    expect(rotated.credentialHandleId).not.toBe(oldHandleId);
    expect(
      database.db
        .prepare("SELECT status, generation FROM credential_handles WHERE id = ?")
        .get(oldHandleId)
    ).toEqual({ status: "revoked", generation: 2 });
    expect(() =>
      authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: harness.providerProof(),
      })
    ).toThrow("invalid or already used");

    setNow(1_000_100);
    const revoked = authority.revokeChannelInstallation({
      actor,
      installationId: installation.id,
      expectedRevision: 2,
    });
    expect(revoked).toMatchObject({ status: "revoked", revision: 3 });
    expect(
      database.db
        .prepare("SELECT status, version FROM link_challenges WHERE installation_id = ?")
        .get(installation.id)
    ).toEqual({ status: "revoked", version: 2 });
    expect(
      database.db
        .prepare("SELECT status, generation FROM credential_handles WHERE id = ?")
        .get(rotated.credentialHandleId)
    ).toEqual({ status: "revoked", generation: 2 });
  });

  it("binds provider proofs to the exact challenge and consumes replay IDs once", () => {
    const harness = createHarness();
    database = harness.database;
    const installation = createInstallation(harness);
    const first = harness.authority.issueLinkChallenge({
      actor: harness.actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });

    expect(() =>
      harness.authority.completeLinkChallenge({
        challenge: first.challenge,
        providerProof: harness.providerProof({
          bindingOverrides: { externalAppId: "attacker-app" },
        }),
      })
    ).toThrow("misbound");
    expect(
      database.db
        .prepare("SELECT status, version FROM link_challenges WHERE user_id = ?")
        .get(harness.actor.userId)
    ).toEqual({ status: "active", version: 1 });

    const replayId = "provider-callback-replay-1";
    const connection = harness.authority.completeLinkChallenge({
      challenge: first.challenge,
      providerProof: harness.providerProof({ replayId }),
    });
    harness.authority.revokeIdentityConnection({
      actor: harness.actor,
      connectionId: connection.id,
      expectedGeneration: 1,
    });
    const second = harness.authority.issueLinkChallenge({
      actor: harness.actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    expect(() =>
      harness.authority.completeLinkChallenge({
        challenge: second.challenge,
        providerProof: harness.providerProof({ replayId }),
      })
    ).toThrow();
    expect(
      database.db
        .prepare("SELECT status, version FROM link_challenges WHERE challenge_digest = ?")
        .get(sha256ForTest(second.challenge))
    ).toEqual({ status: "active", version: 1 });
  });

  it("binds broker registrations and granted scopes to the exact requested authority", () => {
    const harness = createHarness();
    database = harness.database;
    const wrongBinding: CredentialHandleRegistrationExpectation = {
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "installation",
      authorityBinding: {
        kind: "installation",
        teamId: "team-1",
        externalTenantId: "attacker-tenant",
        externalAppId: "app-1",
      },
      replaces: null,
    };
    expect(() =>
      harness.authority.createChannelInstallation({
        actor: harness.actor,
        teamId: "team-1",
        provider: "slack",
        externalTenantId: "tenant-1",
        externalAppId: "app-1",
        expectedBrokerKind: "oauth-envelope",
        credentialBrokerProof: harness.brokerProof(wrongBinding),
        reviewedScopes: ["chat:write", "users:read"],
        capabilities: ["messages:write"],
      })
    ).toThrow("misbound");
    expect(count(database.db, "credential_handles")).toBe(0);

    const installation = createInstallation(harness);
    const issued = harness.authority.issueLinkChallenge({
      actor: harness.actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    expect(() =>
      harness.authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: harness.providerProof({ grantedScopes: ["users:read"] }),
      })
    ).toThrow("misbound");
    expect(database.db.prepare("SELECT status, version FROM link_challenges").get()).toEqual({
      status: "active",
      version: 1,
    });
  });

  it("domain-separates single-use broker receipts by broker and provider", () => {
    const harness = createHarness();
    database = harness.database;
    database.db.exec(`
      INSERT INTO teams (id, name, created_at_ms) VALUES ('team-2', 'Second Team', 100);
      INSERT INTO team_memberships (
        team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
      ) VALUES ('team-2', 'user-1', 'owner', 'active', 1, 100, NULL);
    `);
    const sharedReceiptId = "broker-local-receipt-1";
    const createWithReceipt = (input: {
      teamId: string;
      provider: "slack" | "telegram";
      brokerKind: "oauth-envelope" | "onepassword-connect";
      tenantId: string;
      appId: string;
    }) => {
      const expectation: CredentialHandleRegistrationExpectation = {
        provider: input.provider,
        brokerKind: input.brokerKind,
        usage: "installation",
        authorityBinding: {
          kind: "installation",
          teamId: input.teamId,
          externalTenantId: input.tenantId,
          externalAppId: input.appId,
        },
        replaces: null,
      };
      return harness.authority.createChannelInstallation({
        actor: harness.actor,
        teamId: input.teamId,
        provider: input.provider,
        externalTenantId: input.tenantId,
        externalAppId: input.appId,
        expectedBrokerKind: input.brokerKind,
        credentialBrokerProof: harness.brokerProof(expectation, {
          receiptId: sharedReceiptId,
        }),
        reviewedScopes: ["chat:write"],
        capabilities: ["messages:write"],
      });
    };

    createWithReceipt({
      teamId: "team-1",
      provider: "slack",
      brokerKind: "oauth-envelope",
      tenantId: "slack-tenant",
      appId: "slack-app",
    });
    expect(() =>
      createWithReceipt({
        teamId: "team-1",
        provider: "telegram",
        brokerKind: "onepassword-connect",
        tenantId: "telegram-tenant",
        appId: "telegram-app",
      })
    ).not.toThrow();
    expect(() =>
      createWithReceipt({
        teamId: "team-2",
        provider: "slack",
        brokerKind: "oauth-envelope",
        tenantId: "another-slack-tenant",
        appId: "another-slack-app",
      })
    ).toThrow("UNIQUE constraint failed: credential_handles.broker_receipt_digest");
    expect(count(database.db, "credential_handles")).toBe(2);
  });

  it("rate-limits immutable Link Challenge history after enforcing a useful minimum TTL", () => {
    const harness = createHarness();
    database = harness.database;
    const installation = createInstallation(harness);
    expect(() =>
      harness.authority.issueLinkChallenge({
        actor: harness.actor,
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
        ttlMs: 1,
      })
    ).toThrow("TTL is invalid");

    let now = 1_000_000;
    for (let index = 0; index < 12; index += 1) {
      harness.authority.issueLinkChallenge({
        actor: {
          ...harness.actor,
          authenticatedAtMs: now - 1_000,
          credentialIssuedAtMs: now - 1_000,
        },
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
        ttlMs: 60_000,
      });
      now += 60_001;
      harness.setNow(now);
    }
    expect(() =>
      harness.authority.issueLinkChallenge({
        actor: {
          ...harness.actor,
          authenticatedAtMs: now - 1_000,
          credentialIssuedAtMs: now - 1_000,
        },
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      })
    ).toThrow("issuance rate exceeded");
    expect(count(database.db, "link_challenges")).toBe(12);
  });

  it("relinks only from the terminal historical Identity Connection", () => {
    const harness = createHarness();
    database = harness.database;
    const installation = createInstallation(harness);
    const connectionIds: string[] = [];
    let now = 1_000_000;
    for (let index = 0; index < 3; index += 1) {
      const actor = {
        ...harness.actor,
        authenticatedAtMs: now - 1_000,
        credentialIssuedAtMs: now - 1_000,
      };
      const challenge = harness.authority.issueLinkChallenge({
        actor,
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      });
      const connection = harness.authority.completeLinkChallenge({
        challenge: challenge.challenge,
        providerProof: harness.providerProof({ replayId: `relink-proof-${index}` }),
      });
      connectionIds.push(connection.id);
      if (index < 2) {
        harness.authority.revokeIdentityConnection({
          actor,
          connectionId: connection.id,
          expectedGeneration: 1,
        });
      }
      now += 1_000;
      harness.setNow(now);
    }
    expect(
      database.db
        .prepare(
          "SELECT id, replaces_connection_id FROM identity_connections ORDER BY created_at_ms, id"
        )
        .all()
    ).toEqual([
      { id: connectionIds[0], replaces_connection_id: null },
      { id: connectionIds[1], replaces_connection_id: connectionIds[0] },
      { id: connectionIds[2], replaces_connection_id: connectionIds[1] },
    ]);
  });

  it("never persists raw broker/provider proofs, receipts, replay IDs, or challenges", () => {
    const harness = createHarness();
    database = harness.database;
    const installationBinding: CredentialHandleAuthorityBinding = {
      kind: "installation",
      teamId: "team-1",
      externalTenantId: "tenant-1",
      externalAppId: "app-1",
    };
    const installationExpectation: CredentialHandleRegistrationExpectation = {
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "installation",
      authorityBinding: installationBinding,
      replaces: null,
    };
    const installation = harness.authority.createChannelInstallation({
      actor: harness.actor,
      teamId: "team-1",
      provider: "slack",
      externalTenantId: "tenant-1",
      externalAppId: "app-1",
      expectedBrokerKind: "oauth-envelope",
      credentialBrokerProof: harness.brokerProof(installationExpectation, {
        rawProofCanary: "RAW_BROKER_PROOF_CANARY",
        receiptId: "RAW_BROKER_RECEIPT_CANARY",
      }),
      reviewedScopes: ["chat:write"],
      capabilities: ["messages:write"],
    });
    const issued = harness.authority.issueLinkChallenge({
      actor: harness.actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    const replayId = "RAW_PROVIDER_REPLAY_CANARY";
    const identityExpectation: CredentialHandleRegistrationExpectation = {
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "identity-connection",
      authorityBinding: {
        kind: "identity-connection",
        userId: "user-1",
        installationId: installation.id,
        installationRevision: 1,
        externalTenantId: "tenant-1",
        externalSubject: "external-user-1",
        providerProofReplayDigest: providerProofReplayDigest({
          provider: "slack",
          externalTenantId: "tenant-1",
          externalAppId: "app-1",
          proofReplayId: replayId,
        }),
      },
      replaces: null,
    };
    const connection = harness.authority.completeLinkChallenge({
      challenge: issued.challenge,
      providerProof: harness.providerProof({
        replayId,
        rawProofCanary: "RAW_PROVIDER_PROOF_CANARY",
      }),
      identityCredential: {
        expectedBrokerKind: "oauth-envelope",
        brokerProof: harness.brokerProof(identityExpectation, {
          rawProofCanary: "RAW_IDENTITY_BROKER_PROOF_CANARY",
          receiptId: "RAW_IDENTITY_BROKER_RECEIPT_CANARY",
        }),
      },
    });
    const persisted = JSON.stringify(
      [
        "credential_handles",
        "channel_installations",
        "link_challenges",
        "identity_connections",
        "channel_bindings",
        "connection_authority_ledger",
      ].map((table) => database!.db.prepare(`SELECT * FROM ${table}`).all())
    );
    const exposedViews = JSON.stringify({ installation, connection });
    for (const canary of [
      "RAW_BROKER_PROOF_CANARY",
      "RAW_BROKER_RECEIPT_CANARY",
      "RAW_PROVIDER_PROOF_CANARY",
      "RAW_PROVIDER_REPLAY_CANARY",
      "RAW_IDENTITY_BROKER_PROOF_CANARY",
      "RAW_IDENTITY_BROKER_RECEIPT_CANARY",
      issued.challenge,
    ]) {
      expect(persisted).not.toContain(canary);
      expect(exposedViews).not.toContain(canary);
    }
  });

  it("contains verifier failures behind generic errors", () => {
    const brokerHarness = createHarness({
      verifyCredentialHandleRegistration: ({ expected }) => {
        const registration = {
          ...expected,
          handleId: `txch_v1_${"f".repeat(64)}`,
        } as VerifiedCredentialHandleRegistration;
        Object.defineProperty(registration, "receiptId", {
          get() {
            throw new Error("RAW_BROKER_VERIFIER_ERROR_CANARY");
          },
        });
        return registration;
      },
    });
    database = brokerHarness.database;
    let brokerError = "";
    try {
      createInstallation(brokerHarness);
    } catch (error) {
      brokerError = error instanceof Error ? error.message : String(error);
    }
    expect(brokerError).toBe("Verified Secret Broker registration is invalid or misbound");
    expect(brokerError).not.toContain("CANARY");
    brokerHarness.database.close();
    database = undefined;

    const providerHarness = createHarness({
      verifyProviderProof: () => {
        throw new Error("RAW_PROVIDER_VERIFIER_ERROR_CANARY");
      },
    });
    database = providerHarness.database;
    const installation = createInstallation(providerHarness);
    const issued = providerHarness.authority.issueLinkChallenge({
      actor: providerHarness.actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    let providerError = "";
    try {
      providerHarness.authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: { raw: "RAW_PROVIDER_PROOF_CANARY" },
      });
    } catch (error) {
      providerError = error instanceof Error ? error.message : String(error);
    }
    expect(providerError).toBe("Verified provider proof is invalid or misbound");
    expect(providerError).not.toContain("CANARY");
    expect(
      JSON.stringify(providerHarness.database.db.prepare("SELECT * FROM link_challenges").all())
    ).not.toContain("RAW_PROVIDER_PROOF_CANARY");
  });

  it("contains authentication-snapshot validator failures behind generic errors", () => {
    let issuanceValidatorThrows = false;
    const issuanceHarness = createHarness({
      validateAuthenticationSnapshot: () => {
        if (issuanceValidatorThrows) {
          throw new Error("RAW_AUTH_VALIDATOR_ISSUANCE_CANARY");
        }
        return true;
      },
    });
    database = issuanceHarness.database;
    const issuanceInstallation = createInstallation(issuanceHarness);
    issuanceValidatorThrows = true;
    expect(() =>
      issuanceHarness.authority.issueLinkChallenge({
        actor: issuanceHarness.actor,
        installationId: issuanceInstallation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      })
    ).toThrow("Connection authentication session is unavailable");
    issuanceHarness.database.close();
    database = undefined;

    let completionValidatorThrows = false;
    const completionHarness = createHarness({
      validateAuthenticationSnapshot: () => {
        if (completionValidatorThrows) {
          throw new Error("RAW_AUTH_VALIDATOR_COMPLETION_CANARY");
        }
        return true;
      },
    });
    database = completionHarness.database;
    const completionInstallation = createInstallation(completionHarness);
    const issued = completionHarness.authority.issueLinkChallenge({
      actor: completionHarness.actor,
      installationId: completionInstallation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    completionValidatorThrows = true;
    let completionError = "";
    try {
      completionHarness.authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: completionHarness.providerProof(),
      });
    } catch (error) {
      completionError = error instanceof Error ? error.message : String(error);
    }
    expect(completionError).toBe("Link Challenge authentication session changed");
    expect(completionError).not.toContain("CANARY");
  });

  it("namespaces provider replay digests by provider tenant and application", () => {
    const base = {
      provider: "slack" as const,
      externalTenantId: "tenant-1",
      externalAppId: "app-1",
      proofReplayId: "same-provider-replay-id",
    };
    const digest = providerProofReplayDigest(base);
    expect(providerProofReplayDigest({ ...base, externalAppId: "app-2" })).not.toBe(digest);
    expect(providerProofReplayDigest({ ...base, externalTenantId: "tenant-2" })).not.toBe(digest);
    expect(providerProofReplayDigest({ ...base, provider: "telegram" })).not.toBe(digest);
  });

  it("revalidates the exact authentication session before issuing and consuming", () => {
    const harness = createHarness();
    database = harness.database;
    const installation = createInstallation(harness);
    const issued = harness.authority.issueLinkChallenge({
      actor: harness.actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });

    harness.setAuthenticationActive(false);
    expect(() =>
      harness.authority.completeLinkChallenge({
        challenge: issued.challenge,
        providerProof: harness.providerProof(),
      })
    ).toThrow("authentication session changed");
    expect(() =>
      harness.authority.issueLinkChallenge({
        actor: harness.actor,
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      })
    ).toThrow("authentication session is unavailable");
    expect(database.db.prepare("SELECT status, version FROM link_challenges").get()).toEqual({
      status: "active",
      version: 1,
    });
  });

  it("rejects every cached human mutator after its authentication session is revoked", () => {
    const harness = createHarness({ includeSession: true });
    database = harness.database;
    const installation = createInstallation(harness);
    const challenge = harness.authority.issueLinkChallenge({
      actor: harness.actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    const connection = harness.authority.completeLinkChallenge({
      challenge: challenge.challenge,
      providerProof: harness.providerProof(),
    });
    const binding = harness.authority.createChannelBinding({
      actor: harness.actor,
      sessionId: "session-1",
      installationId: installation.id,
      expectedInstallationRevision: 1,
      conversationKind: "channel",
      externalConversationId: "channel-1",
      inboundPolicy: { mode: "comments-only", requireLinkedIdentity: true },
      outboundPolicy: { mode: "mentions", allowArtifacts: false },
    });
    const before = connectionAuthorityRows(database.db);
    harness.setAuthenticationActive(false);

    const operations: Array<() => unknown> = [
      () => createInstallation(harness),
      () =>
        harness.authority.rotateChannelInstallationCredential({
          actor: harness.actor,
          installationId: installation.id,
          expectedRevision: 1,
          expectedHandleGeneration: 1,
          brokerProof: {},
        }),
      () =>
        harness.authority.revokeChannelInstallation({
          actor: harness.actor,
          installationId: installation.id,
          expectedRevision: 1,
        }),
      () =>
        harness.authority.revokeIdentityConnection({
          actor: harness.actor,
          connectionId: connection.id,
          expectedGeneration: 1,
        }),
      () =>
        harness.authority.createChannelBinding({
          actor: harness.actor,
          sessionId: "session-1",
          installationId: installation.id,
          expectedInstallationRevision: 1,
          conversationKind: "channel",
          externalConversationId: "channel-2",
          inboundPolicy: { mode: "comments-only", requireLinkedIdentity: true },
          outboundPolicy: { mode: "mentions", allowArtifacts: false },
        }),
      () =>
        harness.authority.updateChannelBinding({
          actor: harness.actor,
          bindingId: binding.id,
          expectedRevision: 1,
          expectedInstallationRevision: 1,
          inboundPolicy: { mode: "notifications-only", requireLinkedIdentity: true },
          outboundPolicy: { mode: "disabled", allowArtifacts: false },
        }),
      () =>
        harness.authority.revokeChannelBinding({
          actor: harness.actor,
          bindingId: binding.id,
          expectedRevision: 1,
        }),
    ];
    for (const operation of operations) {
      expect(operation).toThrow("Connection authentication session is unavailable");
    }
    expect(connectionAuthorityRows(database.db)).toEqual(before);
  });

  it("rechecks authentication after installation broker verification before persistence", () => {
    const boundary = { revoke: () => {} };
    const harness = createHarness({
      verifyCredentialHandleRegistration: ({ expected }) => {
        boundary.revoke();
        return {
          ...expected,
          handleId: `txch_v1_${"1".padStart(64, "0")}`,
          receiptId: "create-broker-auth-race",
        };
      },
    });
    boundary.revoke = () => harness.setAuthenticationActive(false);
    database = harness.database;

    expect(() => createInstallation(harness)).toThrow(
      "Connection authentication session is unavailable"
    );
    expect(count(database.db, "credential_handles")).toBe(0);
    expect(count(database.db, "channel_installations")).toBe(0);
    expect(count(database.db, "connection_authority_ledger")).toBe(0);
  });

  it("rolls back rotation when authentication changes during broker verification", () => {
    const boundary = { revoke: () => {} };
    let registrationSequence = 0;
    const harness = createHarness({
      verifyCredentialHandleRegistration: ({ expected }) => {
        registrationSequence += 1;
        if (registrationSequence === 2) boundary.revoke();
        return {
          ...expected,
          handleId: `txch_v1_${registrationSequence.toString(16).padStart(64, "0")}`,
          receiptId: `rotation-broker-auth-race-${registrationSequence}`,
        };
      },
    });
    boundary.revoke = () => harness.setAuthenticationActive(false);
    database = harness.database;
    const installation = createInstallation(harness);
    const before = connectionAuthorityRows(database.db);

    expect(() =>
      harness.authority.rotateChannelInstallationCredential({
        actor: harness.actor,
        installationId: installation.id,
        expectedRevision: 1,
        expectedHandleGeneration: 1,
        brokerProof: { kind: "rotation-proof" },
      })
    ).toThrow("Connection authentication session is unavailable");
    expect(connectionAuthorityRows(database.db)).toEqual(before);
  });

  it("keeps Identity Connection revocation User-owned and revokes its handle atomically", () => {
    const harness = createHarness({ includeMember: true });
    database = harness.database;
    const installation = createInstallation(harness);
    const replayId = "member-provider-proof-1";
    const identityExpectation: CredentialHandleRegistrationExpectation = {
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "identity-connection",
      authorityBinding: {
        kind: "identity-connection",
        userId: "user-2",
        installationId: installation.id,
        installationRevision: 1,
        externalTenantId: "tenant-1",
        externalSubject: "external-user-2",
        providerProofReplayDigest: providerProofReplayDigest({
          provider: "slack",
          externalTenantId: "tenant-1",
          externalAppId: "app-1",
          proofReplayId: replayId,
        }),
      },
      replaces: null,
    };
    const issued = harness.authority.issueLinkChallenge({
      actor: harness.memberActor!,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    const connection = harness.authority.completeLinkChallenge({
      challenge: issued.challenge,
      providerProof: harness.providerProof({
        externalSubject: "external-user-2",
        replayId,
      }),
      identityCredential: {
        expectedBrokerKind: "oauth-envelope",
        brokerProof: harness.brokerProof(identityExpectation),
      },
    });

    expect(() =>
      harness.authority.revokeIdentityConnection({
        actor: harness.actor,
        connectionId: connection.id,
        expectedGeneration: 1,
      })
    ).toThrow("owner authority");
    const revoked = harness.authority.revokeIdentityConnection({
      actor: harness.memberActor!,
      connectionId: connection.id,
      expectedGeneration: 1,
    });
    expect(revoked).toMatchObject({ status: "revoked", generation: 2 });
    expect(
      database.db
        .prepare("SELECT status, generation FROM credential_handles WHERE id = ?")
        .get(connection.credentialHandleId)
    ).toEqual({ status: "revoked", generation: 2 });
  });

  it("caps outstanding Link Challenges and rejects anonymous directive policies", () => {
    const harness = createHarness({ includeSession: true });
    database = harness.database;
    const installation = createInstallation(harness);
    for (let index = 0; index < 3; index += 1) {
      harness.authority.issueLinkChallenge({
        actor: harness.actor,
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      });
    }
    expect(() =>
      harness.authority.issueLinkChallenge({
        actor: harness.actor,
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      })
    ).toThrow("Too many active Link Challenges");
    expect(() =>
      harness.authority.createChannelBinding({
        actor: harness.actor,
        sessionId: "session-1",
        installationId: installation.id,
        expectedInstallationRevision: 1,
        conversationKind: "channel",
        externalConversationId: "channel-1",
        inboundPolicy: { mode: "comments-and-directives", requireLinkedIdentity: false },
        outboundPolicy: { mode: "mentions", allowArtifacts: false },
      })
    ).toThrow("directives require a linked identity");
  });

  it("resolves only exact active ingress/egress fences without granting collaboration access", () => {
    const harness = createHarness({ includeSession: true });
    database = harness.database;
    const installation = createInstallation(harness);
    const replayId = "resolver-provider-proof-1";
    const identityExpectation: CredentialHandleRegistrationExpectation = {
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "identity-connection",
      authorityBinding: {
        kind: "identity-connection",
        userId: "user-1",
        installationId: installation.id,
        installationRevision: 1,
        externalTenantId: "tenant-1",
        externalSubject: "external-user-1",
        providerProofReplayDigest: providerProofReplayDigest({
          provider: "slack",
          externalTenantId: "tenant-1",
          externalAppId: "app-1",
          proofReplayId: replayId,
        }),
      },
      replaces: null,
    };
    const challenge = harness.authority.issueLinkChallenge({
      actor: harness.actor,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      requestedScopes: ["chat:write"],
    });
    const connection = harness.authority.completeLinkChallenge({
      challenge: challenge.challenge,
      providerProof: harness.providerProof({ replayId }),
      identityCredential: {
        expectedBrokerKind: "oauth-envelope",
        brokerProof: harness.brokerProof(identityExpectation),
      },
    });
    const binding = harness.authority.createChannelBinding({
      actor: harness.actor,
      sessionId: "session-1",
      installationId: installation.id,
      expectedInstallationRevision: 1,
      conversationKind: "thread",
      externalConversationId: "channel-1",
      externalThreadId: "thread-1",
      inboundPolicy: { mode: "comments-and-directives", requireLinkedIdentity: true },
      outboundPolicy: { mode: "mentions", allowArtifacts: false },
    });
    const inboundInput = {
      action: "directive" as const,
      provider: "slack" as const,
      installationId: installation.id,
      expectedInstallationRevision: 1,
      bindingId: binding.id,
      expectedBindingRevision: 1,
      externalTenantId: "tenant-1",
      externalSubject: "external-user-1",
      conversationKind: "thread" as const,
      externalConversationId: "channel-1",
      externalThreadId: "thread-1",
    };
    const inbound = harness.authority.resolveInboundAttribution(inboundInput);
    expect(inbound).toMatchObject({
      direction: "inbound",
      action: "directive",
      session: { id: "session-1", teamId: "team-1", accessRevision: 1 },
      installation: { id: installation.id, revision: 1 },
      binding: { id: binding.id, revision: 1 },
      identity: {
        connectionId: connection.id,
        connectionGeneration: 1,
        userId: "user-1",
      },
    });
    expect(JSON.stringify(inbound)).not.toMatch(/"(?:role|membership|participant|allowed)"/);
    expect(
      harness.authority.resolveOutboundBinding({
        bindingId: binding.id,
        expectedBindingRevision: 1,
        expectedInstallationRevision: 1,
        messageKind: "mention",
        includesArtifacts: false,
      })
    ).toMatchObject({
      direction: "outbound",
      session: { id: "session-1" },
      binding: { externalConversationId: "channel-1", externalThreadId: "thread-1" },
    });
    expect(
      harness.authority.resolveInboundAttribution({
        ...inboundInput,
        externalSubject: "someone-else",
      })
    ).toBeNull();

    const narrowed = harness.authority.updateChannelBinding({
      actor: harness.actor,
      bindingId: binding.id,
      expectedRevision: 1,
      expectedInstallationRevision: 1,
      inboundPolicy: { mode: "comments-only", requireLinkedIdentity: true },
      outboundPolicy: { mode: "mentions", allowArtifacts: false },
    });
    expect(narrowed.revision).toBe(2);
    expect(
      harness.authority.resolveInboundAttribution({
        ...inboundInput,
        expectedBindingRevision: 2,
      })
    ).toBeNull();
    expect(
      harness.authority.resolveInboundAttribution({
        ...inboundInput,
        action: "comment",
        expectedBindingRevision: 2,
      })
    ).not.toBeNull();
    expect(
      harness.authority.resolveOutboundBinding({
        bindingId: binding.id,
        expectedBindingRevision: 2,
        expectedInstallationRevision: 1,
        messageKind: "session-message",
        includesArtifacts: false,
      })
    ).toBeNull();
    expect(
      harness.authority.resolveOutboundBinding({
        bindingId: binding.id,
        expectedBindingRevision: 2,
        expectedInstallationRevision: 1,
        messageKind: "mention",
        includesArtifacts: true,
      })
    ).toBeNull();
    expect(
      harness.authority.resolveOutboundBinding({
        bindingId: binding.id,
        expectedBindingRevision: 2,
        expectedInstallationRevision: 1,
        messageKind: "mention",
        includesArtifacts: false,
      })
    ).not.toBeNull();

    harness.authority.revokeChannelInstallation({
      actor: harness.actor,
      installationId: installation.id,
      expectedRevision: 1,
    });
    expect(harness.authority.resolveInboundAttribution(inboundInput)).toBeNull();
    expect(
      harness.authority.resolveOutboundBinding({
        bindingId: binding.id,
        expectedBindingRevision: 1,
        expectedInstallationRevision: 1,
        messageKind: "mention",
        includesArtifacts: false,
      })
    ).toBeNull();
    expect(
      database.db
        .prepare("SELECT status, generation FROM identity_connections WHERE id = ?")
        .get(connection.id)
    ).toEqual({ status: "active", generation: 1 });
    expect(
      database.db
        .prepare("SELECT status, generation FROM credential_handles WHERE id = ?")
        .get(connection.credentialHandleId)
    ).toEqual({ status: "active", generation: 1 });
  });

  it("does not let resolver attribution bypass Team Session participation or steering", async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-connection-kernel-"));
    const filename = path.join(directory, "team-sessions.sqlite");
    const harness = createHarness({ includeSession: true, filename });
    database = harness.database;
    try {
      const installation = createInstallation(harness);
      const challenge = harness.authority.issueLinkChallenge({
        actor: harness.actor,
        installationId: installation.id,
        expectedInstallationRevision: 1,
        requestedScopes: ["chat:write"],
      });
      harness.authority.completeLinkChallenge({
        challenge: challenge.challenge,
        providerProof: harness.providerProof(),
      });
      const binding = harness.authority.createChannelBinding({
        actor: harness.actor,
        sessionId: "session-1",
        installationId: installation.id,
        expectedInstallationRevision: 1,
        conversationKind: "channel",
        externalConversationId: "channel-1",
        inboundPolicy: { mode: "comments-and-directives", requireLinkedIdentity: true },
        outboundPolicy: { mode: "disabled", allowArtifacts: false },
      });
      const attribution = harness.authority.resolveInboundAttribution({
        action: "comment",
        provider: "slack",
        installationId: installation.id,
        expectedInstallationRevision: 1,
        bindingId: binding.id,
        expectedBindingRevision: 1,
        externalTenantId: "tenant-1",
        externalSubject: "external-user-1",
        conversationKind: "channel",
        externalConversationId: "channel-1",
      });
      expect(attribution).not.toBeNull();
      if (!attribution) throw new Error("Expected resolver attribution");

      harness.database.close();
      database = undefined;
      const teamSessions = createTeamSessions({ filename, clock: () => 1_000_000 });
      try {
        const actor = {
          kind: "human" as const,
          userId: attribution.identity.userId,
          displayName: "Attributed external user",
        };
        const base = {
          schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
          actor,
          occurredAtMs: 1_000_000,
        };
        await expect(
          teamSessions.dispatch({
            ...base,
            type: "comment.add",
            sessionId: "session-1",
            body: "Must still require Participant admission",
            idempotency: { scope: "connection-attribution", key: "comment-denial" },
          } as SessionCommand)
        ).rejects.toMatchObject({ code: "not-authorized" });
        await expect(
          teamSessions.dispatch({
            ...base,
            type: "directive.enqueue",
            sessionId: "session-1",
            body: "Must still require active Steerer authority",
            expectedSteeringRevision: attribution.session.steeringRevision,
            idempotency: { scope: "connection-attribution", key: "directive-denial" },
          } as SessionCommand)
        ).rejects.toMatchObject({ code: "not-authorized" });
      } finally {
        teamSessions.close();
      }
    } finally {
      database?.close();
      database = undefined;
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});

function createHarness(
  options: {
    includeMember?: boolean;
    includeSession?: boolean;
    filename?: string;
    verifyCredentialHandleRegistration?: NonNullable<
      CreateConnectionAuthorityOptions["verifyCredentialHandleRegistration"]
    >;
    verifyProviderProof?: NonNullable<CreateConnectionAuthorityOptions["verifyProviderProof"]>;
    validateAuthenticationSnapshot?: NonNullable<
      CreateConnectionAuthorityOptions["validateAuthenticationSnapshot"]
    >;
  } = {}
): {
  database: TeamSessionDatabase;
  authority: ConnectionAuthority;
  actor: ConnectionActorSnapshot;
  memberActor?: ConnectionActorSnapshot;
  brokerProof(
    expectation: CredentialHandleRegistrationExpectation,
    options?: { rawProofCanary?: string; receiptId?: string }
  ): object;
  providerProof(options?: {
    externalSubject?: string;
    replayId?: string;
    bindingOverrides?: Partial<ProviderProofExpectation>;
    grantedScopes?: readonly string[];
    rawProofCanary?: string;
  }): object;
  setAuthenticationActive(value: boolean): void;
  setNow(value: number): void;
} {
  const database = openTeamSessionDatabase({ filename: options.filename ?? ":memory:" });
  seedIdentityAndTeam(database.db, options);
  let now = 1_000_000;
  let generatedId = 0;
  let generatedBytes = 0;
  let handleSequence = 0;
  let providerProofSequence = 0;
  let authenticationActive = true;
  const brokerRegistrations = new WeakMap<object, VerifiedCredentialHandleRegistration>();
  const providerProofs = new WeakMap<
    object,
    {
      externalSubject: string;
      proofReplayId: string;
      bindingOverrides: Partial<ProviderProofExpectation>;
      grantedScopes?: readonly string[];
    }
  >();
  const brokerProof = (
    expectation: CredentialHandleRegistrationExpectation,
    proofOptions: { rawProofCanary?: string; receiptId?: string } = {}
  ): object => {
    const sequence = ++handleSequence;
    const proof = Object.freeze({
      kind: "test-broker-proof",
      sequence,
      ...(proofOptions.rawProofCanary === undefined
        ? {}
        : { rawProofCanary: proofOptions.rawProofCanary }),
    });
    brokerRegistrations.set(proof, {
      ...expectation,
      handleId: `txch_v1_${sequence.toString(16).padStart(64, "0")}`,
      receiptId: proofOptions.receiptId ?? `test-broker-receipt-${sequence}`,
    });
    return proof;
  };
  const providerProof = (
    proofOptions: {
      externalSubject?: string;
      replayId?: string;
      bindingOverrides?: Partial<ProviderProofExpectation>;
      grantedScopes?: readonly string[];
      rawProofCanary?: string;
    } = {}
  ): object => {
    const sequence = ++providerProofSequence;
    const proof = Object.freeze({
      kind: "test-provider-proof",
      sequence,
      ...(proofOptions.rawProofCanary === undefined
        ? {}
        : { rawProofCanary: proofOptions.rawProofCanary }),
    });
    providerProofs.set(proof, {
      externalSubject: proofOptions.externalSubject ?? "external-user-1",
      proofReplayId: proofOptions.replayId ?? `test-provider-replay-${sequence}`,
      bindingOverrides: proofOptions.bindingOverrides ?? {},
      ...(proofOptions.grantedScopes === undefined
        ? {}
        : { grantedScopes: proofOptions.grantedScopes }),
    });
    return proof;
  };
  const authority = createConnectionAuthority({
    db: database.db,
    clock: () => now,
    idGenerator: () => `generated-${++generatedId}`,
    randomBytes: (size) => Buffer.alloc(size, ++generatedBytes),
    verifyCredentialHandleRegistration:
      options.verifyCredentialHandleRegistration ??
      (({ proof }) =>
        typeof proof === "object" && proof !== null
          ? (brokerRegistrations.get(proof) ?? null)
          : null),
    verifyProviderProof:
      options.verifyProviderProof ??
      (({ proof, expected }) => {
        const verified =
          typeof proof === "object" && proof !== null ? providerProofs.get(proof) : undefined;
        if (!verified) return null;
        const grantedScopes = canonicalStringSet(
          verified.grantedScopes ?? expected.requestedScopes,
          "test granted scopes"
        );
        return {
          ...expected,
          ...verified.bindingOverrides,
          externalSubject: verified.externalSubject,
          proofReplayId: verified.proofReplayId,
          grantedScopes: grantedScopes.values,
          grantedScopesDigest: grantedScopes.digest,
        };
      }),
    validateAuthenticationSnapshot:
      options.validateAuthenticationSnapshot ?? (() => authenticationActive),
  });
  return {
    database,
    authority,
    actor: actorSnapshot("user-1", "alice", 999_000),
    ...(options.includeMember ? { memberActor: actorSnapshot("user-2", "bob", 999_000) } : {}),
    brokerProof,
    providerProof,
    setAuthenticationActive(value) {
      authenticationActive = value;
    },
    setNow(value) {
      now = value;
    },
  };
}

function actorSnapshot(
  userId: string,
  subject: string,
  authenticatedAtMs: number
): ConnectionActorSnapshot {
  return {
    userId,
    userGeneration: 1,
    authProvider: "local",
    authSubject: subject,
    authIdentityGeneration: 1,
    authenticatedAtMs,
    credentialIssuedAtMs: authenticatedAtMs,
    credentialExpiresAtMs: authenticatedAtMs + 86_400_000,
    credentialJtiDigest: userId === "user-1" ? "a".repeat(64) : "b".repeat(64),
    device: { provenance: "browser" },
  };
}

function connectionAuthorityRows(db: Database.Database): Record<string, unknown> {
  return {
    handles: db.prepare("SELECT * FROM credential_handles ORDER BY id").all(),
    installations: db.prepare("SELECT * FROM channel_installations ORDER BY id").all(),
    challenges: db.prepare("SELECT * FROM link_challenges ORDER BY id").all(),
    connections: db.prepare("SELECT * FROM identity_connections ORDER BY id").all(),
    bindings: db.prepare("SELECT * FROM channel_bindings ORDER BY id").all(),
    ledger: db.prepare("SELECT * FROM connection_authority_ledger ORDER BY sequence").all(),
  };
}

function createInstallation(harness: ReturnType<typeof createHarness>) {
  const authorityBinding: CredentialHandleAuthorityBinding = {
    kind: "installation",
    teamId: "team-1",
    externalTenantId: "tenant-1",
    externalAppId: "app-1",
  };
  const expectation: CredentialHandleRegistrationExpectation = {
    provider: "slack",
    brokerKind: "oauth-envelope",
    usage: "installation",
    authorityBinding,
    replaces: null,
  };
  return harness.authority.createChannelInstallation({
    actor: harness.actor,
    teamId: "team-1",
    provider: "slack",
    externalTenantId: "tenant-1",
    externalAppId: "app-1",
    expectedBrokerKind: "oauth-envelope",
    credentialBrokerProof: harness.brokerProof(expectation),
    reviewedScopes: ["users:read", "chat:write"],
    capabilities: ["messages:write"],
  });
}

function seedIdentityAndTeam(
  db: Database.Database,
  options: { includeMember?: boolean; includeSession?: boolean }
): void {
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
  if (options.includeMember) {
    db.exec(`
      INSERT INTO users (
        id, username, display_name, legacy_role, status, generation,
        created_at_ms, updated_at_ms, last_login_at_ms, revoked_at_ms
      ) VALUES ('user-2', 'bob', 'Bob', 'user', 'active', 1, 100, 100, 100, NULL);
      INSERT INTO auth_identities (
        id, user_id, provider, subject, status, generation,
        created_at_ms, updated_at_ms, last_authenticated_at_ms, revoked_at_ms
      ) VALUES ('identity-2', 'user-2', 'local', 'bob', 'active', 1, 100, 100, 100, NULL);
      INSERT INTO team_memberships (
        team_id, user_id, role, status, version, created_at_ms, revoked_at_ms
      ) VALUES ('team-1', 'user-2', 'member', 'active', 1, 100, NULL);
    `);
  }
  if (options.includeSession) {
    db.exec(`
      INSERT INTO projects (id, team_id, name, source_ref, created_at_ms)
      VALUES ('project-1', 'team-1', 'Project', NULL, 100);
      INSERT INTO sessions (
        id, team_id, project_id, name, status, steering_policy,
        access_revision, assignee_revision, supervision_revision, steering_revision,
        control_revision, control_epoch, runtime_authorization_generation,
        runtime_authorization_state, run_state_revision, next_sequence,
        runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms
      ) VALUES (
        'session-1', 'team-1', 'project-1', 'Session', 'active', 'shared',
        1, 1, 1, 1, 1, 1, 1, 'enforced', 1, 1,
        'local-tmux', 'trusted-shared-host', 'tmux-session-1', 0, 100
      );
    `);
  }
}

function count(db: Database.Database, table: string): number {
  return (db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count;
}
