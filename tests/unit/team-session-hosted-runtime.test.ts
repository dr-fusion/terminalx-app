import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import {
  commitRuntimeEffectRef,
  digestAggregateEnforcementProof,
  digestRuntimeEnforcementSubject,
  type SynchronousRuntimeEnforcementProofVerifier,
} from "../../src/lib/runtime/runtime-enforcement-proof";
import { digestRunPolicyDraft } from "../../src/lib/team-sessions/run-policy";
import {
  createTeamSessionKernel,
  type RuntimeDeploymentProfile,
} from "../../src/lib/team-sessions/module";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  type ActorContext,
  type RuntimeOutboxDelivery,
  type SessionCommand,
} from "../../src/lib/team-sessions/types";
import { createTestRuntimeCommandAuthorityIssuer } from "../helpers/runtime-authority";
import type { HostedRuntimeAssignmentPlan } from "../../src/lib/runtime/hosted-runtime-control-plane";

const ACTOR: ActorContext = { kind: "human", userId: "user-1", displayName: "Ada" };
const BOB: ActorContext = { kind: "human", userId: "user-2", displayName: "Bob" };
const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);
const DIGEST_C = "c".repeat(64);
const SESSION_ID = "00000000-0000-4000-8000-000000000001";
const STALE_SESSION_ID = "00000000-0000-4000-8000-000000000002";

describe("hosted Team Session Runtime", () => {
  let directory: string | undefined;

  afterEach(() => {
    if (directory) fs.rmSync(directory, { recursive: true, force: true });
    directory = undefined;
  });

  it("persists an exact plan before hosted work and resolves it after restart without tmux state", async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-hosted-session-"));
    const filename = path.join(directory, "sessions.sqlite");
    const profile = hostedProfile();
    let id = 100;
    const options = {
      filename,
      clock: () => 10_000,
      idGenerator: () => `00000000-0000-4000-8000-${String(++id).padStart(12, "0")}`,
      runtimeIncarnationGenerator: () => DIGEST_C,
      runtimeProfile: profile,
      hostedRuntimeObservationProvisioner: hostedObservationProvisioner(),
      hostedRuntimeActivationSource: hostedActivationSource(),
      runtimeCommandAuthorityIssuer: createTestRuntimeCommandAuthorityIssuer(),
      runtimeAuthorizationSnapshotSource: {
        resolve: ({
          runtimeAuthorizationGeneration,
        }: {
          runtimeAuthorizationGeneration: number;
        }) => ({
          generation: runtimeAuthorizationGeneration,
          networkPolicyRef: "network-policy:v1",
          networkPolicyDigest: DIGEST_A,
          credentialPolicyRef: "credential-policy:v1",
          credentialPolicyDigest: DIGEST_B,
          effectEnforcerPolicyDigest: DIGEST_C,
        }),
      },
      runtimeEnforcementProofVerifier: (() => true) as SynchronousRuntimeEnforcementProofVerifier,
    };
    const kernel = createTeamSessionKernel(options);
    await kernel.teamSessions.dispatch(
      command({ type: "team.create", teamId: "team-1", name: "T" }, 1)
    );
    await kernel.teamSessions.dispatch(
      command(
        {
          type: "project.create",
          teamId: "team-1",
          projectId: "project-1",
          name: "P",
        },
        2
      )
    );
    await kernel.teamSessions.dispatch(
      command(
        {
          type: "session.start",
          teamId: "team-1",
          projectId: "project-1",
          sessionId: SESSION_ID,
          name: "Hosted",
        },
        3
      )
    );

    const [delivery] = await kernel.teamSessions.claimRuntimeOutbox({
      workerId: "worker-1",
      leaseDurationMs: 2_000,
    });
    expect(delivery?.kind).toBe("runtime.session.ensure");
    expect(delivery?.payload).toMatchObject({ runtimeKind: "daytona", sessionId: SESSION_ID });
    if (!delivery || delivery.kind !== "runtime.session.ensure") throw new Error("missing ensure");
    const plan = kernel.hostedAssignmentPlanSource.resolve({ kind: "delivery", delivery });
    expect(plan).toMatchObject({
      binding: { sessionId: SESSION_ID },
      runtimeAuthorizationGeneration: 1,
      incarnation: DIGEST_C,
      specificationDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
      effectEnforcerPolicyDigest: DIGEST_C,
      observation: { issuerKeyId: "runtime-observer:v1" },
      capabilities: { yoloEligible: false },
    });
    expect(Object.isFrozen(plan)).toBe(true);
    expect(kernel.hostedAssignmentPlanSource.isCurrent({ kind: "delivery", delivery })).toBe(true);
    if (!plan) throw new Error("missing hosted plan");
    const staleBinding = { ...plan.binding, sandboxGeneration: plan.binding.sandboxGeneration + 1 };
    expect(
      kernel.hostedAssignmentPlanSource.resolve({
        kind: "binding",
        binding: staleBinding,
        runtimeAuthorizationGeneration: 1,
      })
    ).toBeNull();
    expect(
      kernel.hostedAssignmentPlanSource.isCurrent({
        kind: "binding",
        binding: staleBinding,
        runtimeAuthorizationGeneration: 1,
      })
    ).toBe(false);

    const projected = await kernel.teamSessions.inspect({
      type: "session.get",
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      sessionId: SESSION_ID,
      actor: ACTOR,
    });
    expect(projected?.runtime).toEqual({
      kind: "daytona",
      isolation: "isolated-hosted",
      yoloEligible: false,
      authorizationGeneration: 1,
      authorizationState: "pending",
    });
    expect(projected?.runtime).not.toHaveProperty("tmuxName");

    const database = new Database(filename, { readonly: true });
    expect(database.pragma("user_version", { simple: true })).toBe(14);
    expect(
      database
        .prepare(
          `SELECT assignment.status, session.tmux_name, session.yolo_eligible,
                  plan.plan_ref, plan.plan_digest
           FROM runtime_assignments assignment
           JOIN sessions session ON session.id = assignment.session_id
           JOIN hosted_runtime_assignment_plans plan
             ON plan.runtime_assignment_id = assignment.id
           WHERE assignment.session_id = ?`
        )
        .get(SESSION_ID)
    ).toMatchObject({
      status: "provisioning",
      tmux_name: null,
      yolo_eligible: 0,
      plan_ref: expect.any(String),
      plan_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(
      database
        .prepare(
          `SELECT count(*) AS count FROM runtime_receipt_follow_streams
           WHERE runtime_assignment_id = ? AND runtime_authorization_generation = 1`
        )
        .get(plan?.binding.runtimeAssignmentId)
    ).toEqual({ count: 1 });
    database.close();

    expect(
      kernel.hostedAssignmentPlanSource.resolve({
        kind: "session",
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 1,
      })
    ).toBeNull();
    await kernel.teamSessions.markRuntimeOutboxDispatch({
      outboxId: delivery.outboxId,
      workerId: delivery.leaseOwner,
      expectedAttempt: delivery.attempts,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
    });
    await kernel.teamSessions.dispatch({
      type: "runtime.outbox.acknowledge",
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: { kind: "system", userId: "worker-1", displayName: "Runtime worker" },
      idempotency: { scope: "vitest:hosted-worker", key: "ack-1" },
      outboxId: delivery.outboxId,
      workerId: delivery.leaseOwner,
      expectedAttempt: delivery.attempts,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
    });
    expect(kernel.hostedAssignmentPlanSource.isCurrent({ kind: "delivery", delivery })).toBe(true);
    expect(
      kernel.hostedAssignmentPlanSource.resolve({
        kind: "session",
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 1,
      })
    ).toEqual(plan);
    const unconfigured = { kind: "unconfigured" } as const;
    const runPolicy = {
      mode: "autonomous" as const,
      completionPolicy: { kind: "continue-until-all-goals-achieved" as const },
      scopedExternalPolicyRef: "hosted-policy:v1",
      limits: {
        wallClock: unconfigured,
        modelTokens: unconfigured,
        modelSpend: unconfigured,
        outboundBytes: unconfigured,
        actionCounts: {
          local: unconfigured,
          "scoped-external": unconfigured,
          protected: unconfigured,
          forbidden: unconfigured,
        },
      },
    };
    const runStart = (expectedProjectCeilingRevision: string, key: number) =>
      kernel.teamSessions.dispatch(
        command(
          {
            type: "run.start",
            sessionId: SESSION_ID,
            expectedSessionRevision: 1,
            initialGoals: [
              {
                goalId: "goal:hosted",
                position: 1,
                title: "Prove hosted policy binding",
                acceptanceCriteria: ["The durable snapshot uses the hosted ceiling"],
                dependencyGoalIds: [],
              },
            ],
            commit: {
              policy: runPolicy,
              policyDigest: digestRunPolicyDraft(runPolicy),
              expectedProjectCeilingRevision,
              expectedRuntimeAssignmentGeneration: 1,
              expectedSandboxGeneration: 1,
              expectedRuntimeAuthorizationGeneration: 1,
            },
          },
          key
        )
      );
    await expect(runStart("local-tmux-ceiling:v1", 4)).rejects.toMatchObject({
      code: "invalid-command",
    });
    await expect(runStart("hosted-ceiling:v1", 5)).resolves.toMatchObject({
      data: { runPolicyRevision: 1 },
    });
    const policyDatabase = new Database(filename, { readonly: true });
    expect(
      policyDatabase
        .prepare(
          `SELECT project_ceiling_revision, project_ceiling_digest
           FROM run_policy_revisions WHERE session_id = ? AND revision = 1`
        )
        .get(SESSION_ID)
    ).toEqual({ project_ceiling_revision: "hosted-ceiling:v1", project_ceiling_digest: DIGEST_C });
    policyDatabase.close();

    await kernel.teamSessions.dispatch(
      command(
        {
          type: "session.start",
          teamId: "team-1",
          projectId: "project-1",
          sessionId: STALE_SESSION_ID,
          name: "Hosted stale reconciliation",
        },
        6
      )
    );
    const [staleDelivery] = await kernel.teamSessions.claimRuntimeOutbox({
      workerId: "worker-1",
      leaseDurationMs: 2_000,
    });
    if (!staleDelivery || staleDelivery.kind !== "runtime.session.ensure") {
      throw new Error("missing stale ensure");
    }
    await kernel.teamSessions.markRuntimeOutboxDispatch({
      outboxId: staleDelivery.outboxId,
      workerId: staleDelivery.leaseOwner,
      expectedAttempt: staleDelivery.attempts,
      expectedLeaseExpiresAtMs: staleDelivery.leaseExpiresAtMs,
    });
    const racingDatabase = new Database(filename);
    racingDatabase
      .prepare(
        `UPDATE sessions
         SET runtime_authorization_generation = 2, runtime_authorization_state = 'pending'
         WHERE id = ? AND runtime_authorization_generation = 1`
      )
      .run(STALE_SESSION_ID);
    racingDatabase.close();
    await expect(
      kernel.teamSessions.dispatch({
        type: "runtime.outbox.acknowledge",
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: { kind: "system", userId: "worker-1", displayName: "Runtime worker" },
        idempotency: { scope: "vitest:hosted-worker", key: "ack-stale" },
        outboxId: staleDelivery.outboxId,
        workerId: staleDelivery.leaseOwner,
        expectedAttempt: staleDelivery.attempts,
        expectedLeaseExpiresAtMs: staleDelivery.leaseExpiresAtMs,
      })
    ).resolves.toMatchObject({ data: { superseded: true, enforced: false } });
    expect(
      kernel.hostedAssignmentPlanSource.resolve({ kind: "delivery", delivery: staleDelivery })
    ).not.toBeNull();
    expect(
      kernel.hostedAssignmentPlanSource.isCurrent({ kind: "delivery", delivery: staleDelivery })
    ).toBe(false);

    const binding = plan.binding;
    kernel.teamSessions.close();
    const restarted = createTeamSessionKernel(options);
    expect(
      binding &&
        restarted.hostedAssignmentPlanSource.resolve({
          kind: "binding",
          binding,
          runtimeAuthorizationGeneration: 1,
        })
    ).toEqual(plan);
    expect(
      restarted.hostedAssignmentPlanSource.resolve({
        kind: "delivery",
        delivery: staleDelivery,
      })
    ).not.toBeNull();
    expect(
      restarted.hostedAssignmentPlanSource.isCurrent({
        kind: "delivery",
        delivery: staleDelivery,
      })
    ).toBe(false);
    restarted.teamSessions.close();
  });

  it("preserves local v8 data and rejects a malformed v8 outbox before migration", async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-hosted-session-"));
    const filename = path.join(directory, "sessions.sqlite");
    const local = createTeamSessionKernel({ filename });
    await local.teamSessions.dispatch(
      command({ type: "team.create", teamId: "team-1", name: "T" }, 1)
    );
    await local.teamSessions.dispatch(
      command({ type: "project.create", teamId: "team-1", projectId: "project-1", name: "P" }, 2)
    );
    await local.teamSessions.dispatch(
      command(
        {
          type: "session.start",
          teamId: "team-1",
          projectId: "project-1",
          sessionId: SESSION_ID,
          name: "Local",
          tmuxName: "local-v8",
        },
        3
      )
    );
    local.teamSessions.close();

    const v8 = new Database(filename);
    v8.exec(`
      DROP TABLE provider_webhook_deliveries;
      DROP TABLE mobile_auth_migrations;
      DROP TABLE paired_devices;
      DROP TABLE mobile_pairing_codes;
      DROP TABLE connection_authority_ledger;
      DROP TABLE channel_bindings;
      DROP TABLE identity_connections;
      DROP TABLE link_challenges;
      DROP TABLE channel_installations;
      DROP TABLE credential_handles;
      DROP TABLE legacy_google_identity_bridges;
      DROP TABLE local_auth_credentials;
      DROP TABLE auth_identities;
      DROP TABLE users;
      DROP TABLE identity_migrations;
      DROP TRIGGER runtime_effect_enforcer_set_activations_immutable_update;
      DROP TRIGGER runtime_effect_enforcer_set_activations_immutable_delete;
      DROP TABLE runtime_effect_enforcer_set_activations;
      DROP TABLE hosted_runtime_assignment_plans;
    `);
    v8.pragma("user_version = 8");
    v8.close();
    const migrated = createTeamSessionKernel({ filename });
    const session = await migrated.teamSessions.inspect({
      type: "session.get",
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      sessionId: SESSION_ID,
      actor: ACTOR,
    });
    expect(session?.runtime).toMatchObject({
      kind: "local-tmux",
      isolation: "trusted-shared-host",
      tmuxName: "local-v8",
    });
    migrated.teamSessions.close();

    const poisoned = new Database(filename);
    poisoned.exec(`DROP TRIGGER runtime_outbox_immutable_update`);
    poisoned.pragma("ignore_check_constraints = ON");
    poisoned.prepare(`UPDATE runtime_outbox SET payload_json = '{"broken":'`).run();
    poisoned.pragma("user_version = 8");
    poisoned.close();
    expect(() => createTeamSessionKernel({ filename })).toThrow(/malformed JSON|payload contract/);
  });

  it("recreates v8 parent artifacts idempotently and rejects hosted-looking v8 work", async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-hosted-session-"));
    const artifactFilename = path.join(directory, "artifacts.sqlite");
    const local = createTeamSessionKernel({ filename: artifactFilename });
    await local.teamSessions.dispatch(
      command({ type: "team.create", teamId: "team-1", name: "T" }, 1)
    );
    await local.teamSessions.dispatch(
      command({ type: "project.create", teamId: "team-1", projectId: "project-1", name: "P" }, 2)
    );
    await local.teamSessions.dispatch(
      command(
        {
          type: "session.start",
          teamId: "team-1",
          projectId: "project-1",
          sessionId: SESSION_ID,
          name: "Artifact migration",
          tmuxName: "artifact-migration",
        },
        3
      )
    );
    local.teamSessions.close();
    const v8 = new Database(artifactFilename);
    v8.exec(`
      DROP TABLE provider_webhook_deliveries;
      DROP TABLE mobile_auth_migrations;
      DROP TABLE paired_devices;
      DROP TABLE mobile_pairing_codes;
      DROP TABLE connection_authority_ledger;
      DROP TABLE channel_bindings;
      DROP TABLE identity_connections;
      DROP TABLE link_challenges;
      DROP TABLE channel_installations;
      DROP TABLE credential_handles;
      DROP TABLE legacy_google_identity_bridges;
      DROP TABLE local_auth_credentials;
      DROP TABLE auth_identities;
      DROP TABLE users;
      DROP TABLE identity_migrations;
      DROP TRIGGER runtime_effect_enforcer_set_activations_immutable_update;
      DROP TRIGGER runtime_effect_enforcer_set_activations_immutable_delete;
      DROP TABLE runtime_effect_enforcer_set_activations;
      DROP TABLE hosted_runtime_assignment_plans;
      CREATE INDEX migration_probe_sessions_status ON sessions(status);
      CREATE TRIGGER migration_probe_assignment_insert
      AFTER INSERT ON runtime_assignments BEGIN SELECT 1; END;
      PRAGMA user_version = 8;
    `);
    v8.close();

    createTeamSessionKernel({ filename: artifactFilename }).teamSessions.close();
    createTeamSessionKernel({ filename: artifactFilename }).teamSessions.close();
    const migrated = new Database(artifactFilename, { readonly: true });
    try {
      expect(migrated.pragma("user_version", { simple: true })).toBe(14);
      expect(migrated.pragma("foreign_key_check")).toEqual([]);
      expect(migrated.pragma("quick_check", { simple: true })).toBe("ok");
      expect(
        migrated
          .prepare(
            `SELECT type, name FROM sqlite_schema
             WHERE name IN ('migration_probe_sessions_status', 'migration_probe_assignment_insert')
             ORDER BY type, name`
          )
          .all()
      ).toEqual([
        { type: "index", name: "migration_probe_sessions_status" },
        { type: "trigger", name: "migration_probe_assignment_insert" },
      ]);
    } finally {
      migrated.close();
    }

    const poisonedFilename = path.join(directory, "hosted-looking-v8.sqlite");
    const poisonedKernel = createTeamSessionKernel({ filename: poisonedFilename });
    await poisonedKernel.teamSessions.dispatch(
      command({ type: "team.create", teamId: "team-2", name: "T2" }, 11)
    );
    await poisonedKernel.teamSessions.dispatch(
      command({ type: "project.create", teamId: "team-2", projectId: "project-2", name: "P2" }, 12)
    );
    await poisonedKernel.teamSessions.dispatch(
      command(
        {
          type: "session.start",
          teamId: "team-2",
          projectId: "project-2",
          sessionId: STALE_SESSION_ID,
          name: "Poisoned v8",
          tmuxName: "poisoned-v8",
        },
        13
      )
    );
    poisonedKernel.teamSessions.close();
    const poisoned = new Database(poisonedFilename);
    poisoned.exec(`
      DROP TABLE hosted_runtime_assignment_plans;
      DROP TRIGGER runtime_outbox_immutable_update;
      PRAGMA user_version = 8;
    `);
    poisoned.prepare(`UPDATE runtime_outbox SET payload_json = ? WHERE session_id = ?`).run(
      JSON.stringify({
        sessionId: STALE_SESSION_ID,
        runtimeKind: "daytona",
        runtimeAuthorizationGeneration: 1,
        binding: {
          teamId: "team-2",
          projectId: "project-2",
          sessionId: STALE_SESSION_ID,
          runtimeAssignmentId: "poisoned-assignment",
          runtimeAssignmentGeneration: 1,
          sandboxId: "poisoned-sandbox",
          sandboxGeneration: 1,
          runtimePrincipalId: "poisoned-principal",
        },
        assignmentPlanRef: "poisoned-plan",
        assignmentPlanDigest: DIGEST_A,
      }),
      STALE_SESSION_ID
    );
    poisoned.close();
    expect(() => createTeamSessionKernel({ filename: poisonedFilename })).toThrow(
      /Runtime outbox .*payload contract/
    );
    const rolledBack = new Database(poisonedFilename, { readonly: true });
    try {
      expect(rolledBack.pragma("user_version", { simple: true })).toBe(8);
      expect(
        rolledBack
          .prepare(
            `SELECT name FROM sqlite_schema
             WHERE type = 'table' AND name = 'hosted_runtime_assignment_plans'`
          )
          .get()
      ).toBeUndefined();
    } finally {
      rolledBack.close();
    }
  });

  it.each(["ensure-first", "retire-first", "ensure-terminal-failure"] as const)(
    "recovers a fenced hosted Run with independent %s acknowledgement",
    async (acknowledgementOrder) => {
      directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-hosted-session-"));
      const filename = path.join(directory, "sessions.sqlite");
      let id = acknowledgementOrder === "retire-first" ? 900 : 300;
      const options = {
        filename,
        clock: () => 20_000,
        idGenerator: () =>
          `00000000-0000-4000-8000-${String(
            acknowledgementOrder === "retire-first" ? --id : ++id
          ).padStart(12, "0")}`,
        runtimeIncarnationGenerator: () => DIGEST_C,
        runtimeProfile: hostedProfile(),
        ...hostedSecurity(),
      };
      let kernel = createTeamSessionKernel(options);
      await kernel.teamSessions.dispatch(
        command({ type: "team.create", teamId: "team-1", name: "T" }, 1)
      );
      await kernel.teamSessions.dispatch(
        command({ type: "project.create", teamId: "team-1", projectId: "project-1", name: "P" }, 2)
      );
      await kernel.teamSessions.dispatch(
        command(
          {
            type: "session.start",
            teamId: "team-1",
            projectId: "project-1",
            sessionId: SESSION_ID,
            name: "Fence the existing provider instance",
          },
          3
        )
      );
      const [ensure] = await kernel.teamSessions.claimRuntimeOutbox({
        workerId: "worker-1",
        leaseDurationMs: 2_000,
      });
      if (
        !ensure ||
        ensure.kind !== "runtime.session.ensure" ||
        ensure.payload.runtimeKind !== "daytona"
      ) {
        throw new Error("missing hosted ensure");
      }
      const originalPlan = kernel.hostedAssignmentPlanSource.resolve({
        kind: "delivery",
        delivery: ensure,
      });
      if (!originalPlan) throw new Error("missing original hosted plan");
      await kernel.teamSessions.markRuntimeOutboxDispatch({
        outboxId: ensure.outboxId,
        workerId: ensure.leaseOwner,
        expectedAttempt: ensure.attempts,
        expectedLeaseExpiresAtMs: ensure.leaseExpiresAtMs,
      });
      await kernel.teamSessions.dispatch({
        type: "runtime.outbox.acknowledge",
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: { kind: "system", userId: "worker-1", displayName: "Runtime worker" },
        idempotency: { scope: "vitest:hosted-fence", key: "ensure" },
        outboxId: ensure.outboxId,
        workerId: ensure.leaseOwner,
        expectedAttempt: ensure.attempts,
        expectedLeaseExpiresAtMs: ensure.leaseExpiresAtMs,
      });
      const unconfigured = { kind: "unconfigured" } as const;
      const runPolicy = {
        mode: "autonomous" as const,
        completionPolicy: { kind: "continue-until-all-goals-achieved" as const },
        scopedExternalPolicyRef: "hosted-policy:v1",
        limits: {
          wallClock: unconfigured,
          modelTokens: unconfigured,
          modelSpend: unconfigured,
          outboundBytes: unconfigured,
          actionCounts: {
            local: unconfigured,
            "scoped-external": unconfigured,
            protected: unconfigured,
            forbidden: unconfigured,
          },
        },
      };
      await kernel.teamSessions.dispatch(
        command(
          {
            type: "run.start",
            sessionId: SESSION_ID,
            expectedSessionRevision: 1,
            initialGoals: [
              {
                goalId: "goal:fence",
                position: 1,
                title: "Pause on Assignee loss",
                acceptanceCriteria: ["Hosted state remains truthful"],
                dependencyGoalIds: [],
              },
            ],
            commit: {
              policy: runPolicy,
              policyDigest: digestRunPolicyDraft(runPolicy),
              expectedProjectCeilingRevision: "hosted-ceiling:v1",
              expectedRuntimeAssignmentGeneration: 1,
              expectedSandboxGeneration: 1,
              expectedRuntimeAuthorizationGeneration: 1,
            },
          },
          4
        )
      );
      await enforceRuntimeLifecycle(kernel.runtimeLifecycleJournal, "run.start", 20_000);

      await kernel.teamSessions.dispatch(
        command(
          {
            type: "team.membership.grant",
            teamId: "team-1",
            userId: BOB.userId,
            role: "owner",
            expectedMembershipVersion: 0,
          },
          5
        )
      );
      await kernel.teamSessions.dispatch(
        command(
          {
            type: "project.access.grant",
            projectId: "project-1",
            userId: BOB.userId,
            role: "contributor",
            expectedAccessVersion: 0,
          },
          6
        )
      );
      const beforeParticipant = await kernel.teamSessions.inspect({
        type: "session.get",
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        sessionId: SESSION_ID,
        actor: ACTOR,
      });
      if (!beforeParticipant) throw new Error("missing Session");
      await kernel.teamSessions.dispatch(
        command(
          {
            type: "session.participant.grant",
            sessionId: SESSION_ID,
            userId: BOB.userId,
            expectedParticipantVersion: 0,
            expectedAccessRevision: beforeParticipant.accessRevision,
          },
          7
        )
      );
      const access = await kernel.teamSessions.inspect({
        type: "team.access",
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        teamId: "team-1",
        actor: BOB,
      });
      const starter = access.memberships.find((membership) => membership.userId === ACTOR.userId);
      if (!starter) throw new Error("missing starter membership");
      await kernel.teamSessions.dispatch(
        command(
          {
            type: "team.membership.revoke",
            teamId: "team-1",
            userId: ACTOR.userId,
            expectedMembershipVersion: starter.version,
          },
          8,
          BOB
        )
      );

      const [fence] = await kernel.teamSessions.claimRuntimeOutbox({
        workerId: "worker-1",
        leaseDurationMs: 2_000,
      });
      if (
        !fence ||
        fence.kind !== "runtime.authorization.fence" ||
        !("runtimeKind" in fence.payload) ||
        fence.payload.runtimeKind !== "daytona"
      ) {
        throw new Error("missing hosted fence");
      }
      expect(fence.payload).toMatchObject({
        runtimeAuthorizationGeneration: 2,
        assignmentPlanRuntimeAuthorizationGeneration: 1,
        assignmentPlanRef: ensure.payload.assignmentPlanRef,
        assignmentPlanDigest: ensure.payload.assignmentPlanDigest,
        binding: originalPlan.binding,
      });
      expect(
        kernel.hostedAssignmentPlanSource.resolve({ kind: "delivery", delivery: fence })
      ).toEqual(originalPlan);
      expect(
        kernel.hostedAssignmentPlanSource.isCurrent({ kind: "delivery", delivery: fence })
      ).toBe(true);

      const database = new Database(filename);
      try {
        expect(
          database
            .prepare(
              `SELECT assignment.runtime_authorization_generation, assignment.status,
                    count(plan.plan_ref) AS plan_count
             FROM runtime_assignments assignment
             JOIN hosted_runtime_assignment_plans plan
               ON plan.runtime_assignment_id = assignment.id
             WHERE assignment.session_id = ?`
            )
            .get(SESSION_ID)
        ).toEqual({ runtime_authorization_generation: 2, status: "recovering", plan_count: 1 });
        const durableFence = database
          .prepare(
            `SELECT session_sequence, payload_json, created_at_ms FROM runtime_outbox WHERE id = ?`
          )
          .get(fence.outboxId) as {
          session_sequence: number;
          payload_json: string;
          created_at_ms: number;
        };
        const poisonedPayload = JSON.parse(durableFence.payload_json) as Record<string, unknown>;
        poisonedPayload.assignmentPlanRuntimeAuthorizationGeneration = 2;
        expect(() =>
          database
            .prepare(
              `INSERT INTO runtime_outbox
               (id, session_id, session_sequence, kind, payload_json, status, attempts, created_at_ms)
             VALUES ('poisoned-hosted-fence', ?, ?, 'runtime.authorization.fence', ?, 'pending', 0, ?)`
            )
            .run(
              SESSION_ID,
              durableFence.session_sequence,
              JSON.stringify(poisonedPayload),
              durableFence.created_at_ms
            )
        ).toThrow(/payload contract|source event/);
      } finally {
        database.close();
      }

      const beforeFenceAcknowledgement = await kernel.teamSessions.inspect({
        type: "session.get",
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        sessionId: SESSION_ID,
        actor: BOB,
      });
      if (!beforeFenceAcknowledgement) throw new Error("missing fenced Session");
      const claimCommand = command(
        {
          type: "session.assignee.claim",
          sessionId: SESSION_ID,
          expectedAssigneeRevision: beforeFenceAcknowledgement.assigneeRevision,
          expectedAccessRevision: beforeFenceAcknowledgement.accessRevision,
        },
        9,
        BOB
      );
      await expect(kernel.teamSessions.dispatch(claimCommand)).rejects.toMatchObject({
        code: "conflict",
      });

      await kernel.teamSessions.markRuntimeOutboxDispatch({
        outboxId: fence.outboxId,
        workerId: fence.leaseOwner,
        expectedAttempt: fence.attempts,
        expectedLeaseExpiresAtMs: fence.leaseExpiresAtMs,
      });
      const acknowledged = await kernel.teamSessions.dispatch({
        type: "runtime.outbox.acknowledge",
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: { kind: "system", userId: "worker-1", displayName: "Runtime worker" },
        idempotency: { scope: "vitest:hosted-fence", key: "fence" },
        outboxId: fence.outboxId,
        workerId: fence.leaseOwner,
        expectedAttempt: fence.attempts,
        expectedLeaseExpiresAtMs: fence.leaseExpiresAtMs,
      });
      expect(acknowledged.data).toMatchObject({ enforced: false, superseded: false });
      const awaiting = await kernel.teamSessions.inspect({
        type: "session.get",
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        sessionId: SESSION_ID,
        actor: BOB,
      });
      expect(awaiting).toMatchObject({
        status: "awaiting_assignee",
        runtime: { authorizationGeneration: 2, authorizationState: "pending" },
      });
      if (!awaiting) throw new Error("missing awaiting Session");
      const claimResult = await kernel.teamSessions.dispatch(claimCommand);
      await expect(kernel.teamSessions.dispatch(claimCommand)).resolves.toMatchObject({
        accepted: true,
        replayed: true,
        data: claimResult.data,
      });
      await expect(
        kernel.teamSessions.dispatch({
          ...claimCommand,
          idempotency: { scope: "vitest:hosted", key: "competing-assignee-claim" },
        })
      ).rejects.toMatchObject({ code: "stale-revision" });
      const recoveryCardinality = new Database(filename, { readonly: true });
      try {
        expect(
          recoveryCardinality
            .prepare(
              `SELECT
               (SELECT count(*) FROM session_events
                WHERE session_id = ?
                  AND type = 'session.hosted-runtime.recovery.requested') AS event_count,
               (SELECT count(*) FROM runtime_outbox outbox
                JOIN session_events event
                  ON event.session_id = outbox.session_id
                 AND event.sequence = outbox.session_sequence
                WHERE event.session_id = ?
                  AND event.type = 'session.hosted-runtime.recovery.requested') AS outbox_count`
            )
            .get(SESSION_ID, SESSION_ID)
        ).toEqual({ event_count: 1, outbox_count: 2 });
      } finally {
        recoveryCardinality.close();
      }
      if (acknowledgementOrder === "retire-first") {
        kernel.teamSessions.close();
        kernel = createTeamSessionKernel(options);
      }
      const claimed = await kernel.teamSessions.inspect({
        type: "session.get",
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        sessionId: SESSION_ID,
        actor: BOB,
      });
      expect(claimed).toMatchObject({
        status: "active",
        runtime: { authorizationGeneration: 3, authorizationState: "pending" },
      });
      const truthful = new Database(filename, { readonly: true });
      try {
        expect(
          truthful
            .prepare(
              `SELECT assignment.status, run.lifecycle
             FROM runtime_assignments assignment
             JOIN agent_runs run ON run.runtime_assignment_id = assignment.id
             WHERE assignment.session_id = ?`
            )
            .get(SESSION_ID)
        ).toEqual({ status: "recovering", lifecycle: "paused" });
        expect(
          truthful
            .prepare(
              `SELECT count(*) AS count FROM hosted_runtime_assignment_plans
             WHERE runtime_assignment_id = ?`
            )
            .get(originalPlan.binding.runtimeAssignmentId)
        ).toEqual({ count: 1 });
      } finally {
        truthful.close();
      }

      const [firstRecoveryDelivery] = await kernel.teamSessions.claimRuntimeOutbox({
        workerId: "worker-1",
        leaseDurationMs: 2_000,
      });
      let recoveryRetire:
        | Extract<RuntimeOutboxDelivery, { kind: "runtime.session.retire" }>
        | undefined;
      let recoveryRetireAcknowledged = false;
      if (firstRecoveryDelivery?.kind === "runtime.session.retire") {
        recoveryRetire = firstRecoveryDelivery;
        expect(
          kernel.hostedAssignmentPlanSource.isCurrent({
            kind: "delivery",
            delivery: recoveryRetire,
          })
        ).toBe(true);
        expect(recoveryRetire.payload).toMatchObject({
          reason: "assignee-replacement",
          runtimeAuthorizationGeneration: 3,
          previousRuntimeAuthorizationGeneration: 2,
          binding: originalPlan.binding,
        });
        await acknowledgeRuntimeDelivery(kernel, recoveryRetire, "recovery-retire-first");
        recoveryRetireAcknowledged = true;
        const retiredBeforeEnsure = new Database(filename, { readonly: true });
        try {
          expect(
            retiredBeforeEnsure
              .prepare(
                `SELECT assignment.status, run.runtime_assignment_id,
                      session.runtime_authorization_state
               FROM runtime_assignments assignment
               JOIN agent_runs run ON run.runtime_assignment_id = assignment.id
               JOIN sessions session ON session.id = run.session_id
               WHERE assignment.id = ?`
              )
              .get(originalPlan.binding.runtimeAssignmentId)
          ).toEqual({
            status: "retired",
            runtime_assignment_id: originalPlan.binding.runtimeAssignmentId,
            runtime_authorization_state: "pending",
          });
        } finally {
          retiredBeforeEnsure.close();
        }
      }
      const [claimedEnsure] =
        firstRecoveryDelivery?.kind === "runtime.session.ensure"
          ? [firstRecoveryDelivery]
          : await kernel.teamSessions.claimRuntimeOutbox({
              workerId: "worker-1",
              leaseDurationMs: 2_000,
            });
      let recoveryEnsure = claimedEnsure;
      if (
        !recoveryEnsure ||
        recoveryEnsure.kind !== "runtime.session.ensure" ||
        recoveryEnsure.payload.runtimeKind !== "daytona" ||
        !("recoveryId" in recoveryEnsure.payload)
      ) {
        throw new Error("missing hosted recovery ensure");
      }
      const recoveryPoison = new Database(filename);
      try {
        const durableRecovery = recoveryPoison
          .prepare(
            `SELECT session_sequence, payload_json, created_at_ms
           FROM runtime_outbox WHERE id = ?`
          )
          .get(recoveryEnsure.outboxId) as {
          session_sequence: number;
          payload_json: string;
          created_at_ms: number;
        };
        const poisonedRecoveryPayload = JSON.parse(durableRecovery.payload_json) as {
          previousBinding: { sandboxId: string };
        };
        poisonedRecoveryPayload.previousBinding.sandboxId = "poisoned-old-sandbox";
        expect(() =>
          recoveryPoison
            .prepare(
              `INSERT INTO runtime_outbox
               (id, session_id, session_sequence, kind, payload_json,
                status, attempts, created_at_ms)
             VALUES ('poisoned-recovery-ensure', ?, ?, 'runtime.session.ensure', ?,
                     'pending', 0, ?)`
            )
            .run(
              SESSION_ID,
              durableRecovery.session_sequence,
              JSON.stringify(poisonedRecoveryPayload),
              durableRecovery.created_at_ms
            )
        ).toThrow(/source event does not match/);
      } finally {
        recoveryPoison.close();
      }
      if (acknowledgementOrder === "ensure-terminal-failure") {
        await kernel.teamSessions.markRuntimeOutboxDispatch({
          outboxId: recoveryEnsure.outboxId,
          workerId: recoveryEnsure.leaseOwner,
          expectedAttempt: recoveryEnsure.attempts,
          expectedLeaseExpiresAtMs: recoveryEnsure.leaseExpiresAtMs,
        });
        await kernel.teamSessions.dispatch({
          type: "runtime.outbox.fail",
          schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
          actor: {
            kind: "system",
            userId: recoveryEnsure.leaseOwner,
            displayName: "Runtime worker",
          },
          idempotency: {
            scope: "vitest:hosted-recovery-worker",
            key: "recovery-ensure-terminal-failure",
          },
          outboxId: recoveryEnsure.outboxId,
          workerId: recoveryEnsure.leaseOwner,
          expectedAttempt: recoveryEnsure.attempts,
          expectedLeaseExpiresAtMs: recoveryEnsure.leaseExpiresAtMs,
          retryable: false,
          errorCode: "runtime_permission_denied",
        });
        const failed = new Database(filename, { readonly: true });
        try {
          expect(
            failed
              .prepare(
                `SELECT session.runtime_authorization_state, run.lifecycle,
                      run.runtime_assignment_id, replacement.status AS replacement_status
               FROM sessions session
               JOIN agent_runs run ON run.session_id = session.id
               JOIN runtime_assignments replacement ON replacement.id = ?
               WHERE session.id = ?`
              )
              .get(recoveryEnsure.payload.binding.runtimeAssignmentId, SESSION_ID)
          ).toEqual({
            runtime_authorization_state: "quarantined",
            lifecycle: "paused",
            runtime_assignment_id: originalPlan.binding.runtimeAssignmentId,
            replacement_status: "quarantined",
          });
        } finally {
          failed.close();
        }
        expect(
          await kernel.teamSessions.claimRuntimeOutbox({
            workerId: "worker-1",
            leaseDurationMs: 2_000,
          })
        ).toEqual([]);
        kernel.teamSessions.close();
        return;
      }
      if (acknowledgementOrder === "ensure-first") {
        await kernel.teamSessions.markRuntimeOutboxDispatch({
          outboxId: recoveryEnsure.outboxId,
          workerId: recoveryEnsure.leaseOwner,
          expectedAttempt: recoveryEnsure.attempts,
          expectedLeaseExpiresAtMs: recoveryEnsure.leaseExpiresAtMs,
        });
        await kernel.teamSessions.dispatch({
          type: "runtime.outbox.fail",
          schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
          actor: {
            kind: "system",
            userId: recoveryEnsure.leaseOwner,
            displayName: "Runtime worker",
          },
          idempotency: {
            scope: "vitest:hosted-recovery-worker",
            key: "recovery-ensure-retry",
          },
          outboxId: recoveryEnsure.outboxId,
          workerId: recoveryEnsure.leaseOwner,
          expectedAttempt: recoveryEnsure.attempts,
          expectedLeaseExpiresAtMs: recoveryEnsure.leaseExpiresAtMs,
          retryable: true,
          errorCode: "runtime_timeout",
        });
        const [retriedEnsure] = await kernel.teamSessions.claimRuntimeOutbox({
          workerId: "worker-1",
          leaseDurationMs: 2_000,
        });
        if (
          !retriedEnsure ||
          retriedEnsure.kind !== "runtime.session.ensure" ||
          retriedEnsure.payload.runtimeKind !== "daytona" ||
          !("recoveryId" in retriedEnsure.payload)
        ) {
          throw new Error("missing hosted recovery reconciliation");
        }
        expect(retriedEnsure.dispatchMode).toBe("reconcile");
        recoveryEnsure = retriedEnsure;
      }
      expect(recoveryEnsure.payload).toMatchObject({
        runtimeAuthorizationGeneration: 3,
        previousRuntimeAuthorizationGeneration: 2,
        previousBinding: originalPlan.binding,
        previousAssignmentPlanRuntimeAuthorizationGeneration: 1,
      });
      const replacementPlan = kernel.hostedAssignmentPlanSource.resolve({
        kind: "delivery",
        delivery: recoveryEnsure,
      });
      expect(replacementPlan?.binding.runtimeAssignmentId).not.toBe(
        originalPlan.binding.runtimeAssignmentId
      );
      expect(replacementPlan?.observation).not.toEqual(originalPlan.observation);
      expect(
        kernel.hostedAssignmentPlanSource.isCurrent({
          kind: "delivery",
          delivery: recoveryEnsure,
        })
      ).toBe(true);
      await acknowledgeRuntimeDelivery(kernel, recoveryEnsure, "recovery-ensure");
      expect(
        kernel.hostedAssignmentPlanSource.resolve({
          kind: "session",
          sessionId: SESSION_ID,
          runtimeAuthorizationGeneration: 3,
        })
      ).toEqual(replacementPlan);

      const rebound = new Database(filename, { readonly: true });
      let reboundStateVersion = 0;
      try {
        const recovered = rebound
          .prepare(
            `SELECT run.lifecycle, run.state_version, run.runtime_assignment_id,
                  run.runtime_authorization_generation, run.current_policy_revision,
                  session.runtime_authorization_state
           FROM agent_runs run
           JOIN sessions session ON session.id = run.session_id
           WHERE run.session_id = ?`
          )
          .get(SESSION_ID) as Record<string, unknown>;
        expect(recovered).toEqual({
          lifecycle: "paused",
          state_version: 5,
          runtime_assignment_id: replacementPlan?.binding.runtimeAssignmentId,
          runtime_authorization_generation: 3,
          current_policy_revision: 2,
          runtime_authorization_state: "enforced",
        });
        reboundStateVersion = recovered.state_version as number;
      } finally {
        rebound.close();
      }
      if (!("agentRunId" in recoveryEnsure.payload)) {
        throw new Error("missing hosted recovery Run identity");
      }
      const recoveryAgentRunId = recoveryEnsure.payload.agentRunId;
      await expect(
        kernel.teamSessions.dispatch(
          command(
            {
              type: "run.resume",
              sessionId: SESSION_ID,
              agentRunId: recoveryAgentRunId,
              expectedRunStateVersion: reboundStateVersion,
              expectedRunPolicyRevision: 2,
              expectedRuntimeAuthorizationGeneration: 3,
            },
            10,
            BOB
          )
        )
      ).resolves.toMatchObject({ data: { runtimeCommandStatus: "pending" } });
      await enforceRuntimeLifecycle(kernel.runtimeLifecycleJournal, "run.resume", 20_000);
      if (acknowledgementOrder === "ensure-first") {
        const laterFence = new Database(filename);
        try {
          laterFence
            .prepare(
              `UPDATE sessions
             SET runtime_authorization_generation = 4,
                 runtime_authorization_state = 'pending'
             WHERE id = ? AND runtime_authorization_generation = 3`
            )
            .run(SESSION_ID);
        } finally {
          laterFence.close();
        }
      }

      if (!recoveryRetire) {
        const [claimedRetire] = await kernel.teamSessions.claimRuntimeOutbox({
          workerId: "worker-1",
          leaseDurationMs: 2_000,
        });
        if (!claimedRetire || claimedRetire.kind !== "runtime.session.retire") {
          throw new Error("missing hosted recovery retire");
        }
        recoveryRetire = claimedRetire;
      }
      if (!recoveryRetire || recoveryRetire.kind !== "runtime.session.retire") {
        throw new Error("missing hosted recovery retire");
      }
      if (!recoveryRetireAcknowledged) {
        expect(
          kernel.hostedAssignmentPlanSource.isCurrent({
            kind: "delivery",
            delivery: recoveryRetire,
          })
        ).toBe(true);
      }
      expect(recoveryRetire.payload).toMatchObject({
        reason: "assignee-replacement",
        runtimeAuthorizationGeneration: 3,
        previousRuntimeAuthorizationGeneration: 2,
        binding: originalPlan.binding,
        replacementBinding: replacementPlan?.binding,
      });
      if (!recoveryRetireAcknowledged) {
        await acknowledgeRuntimeDelivery(kernel, recoveryRetire, "recovery-retire");
      }
      const retired = new Database(filename, { readonly: true });
      try {
        expect(
          retired
            .prepare(`SELECT status FROM runtime_assignments WHERE id = ?`)
            .get(originalPlan.binding.runtimeAssignmentId)
        ).toEqual({ status: "retired" });
        expect(
          retired
            .prepare(
              `SELECT count(*) AS count,
                    count(DISTINCT issuer_key_id) AS issuer_count,
                    count(DISTINCT public_key_spki_digest) AS key_count
             FROM runtime_principal_observation_keys
             WHERE session_id = ?`
            )
            .get(SESSION_ID)
        ).toEqual({ count: 2, issuer_count: 2, key_count: 2 });
      } finally {
        retired.close();
        kernel.teamSessions.close();
      }
    }
  );

  it("rejects user-selected profiles and mismatched hosted Runtime pairs", async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-hosted-session-"));
    const filename = path.join(directory, "sessions.sqlite");
    const kernel = createTeamSessionKernel({ filename });
    await kernel.teamSessions.dispatch(
      command({ type: "team.create", teamId: "team-1", name: "T" }, 1)
    );
    await kernel.teamSessions.dispatch(
      command({ type: "project.create", teamId: "team-1", projectId: "project-1", name: "P" }, 2)
    );
    await kernel.teamSessions.dispatch(
      command(
        {
          type: "session.start",
          teamId: "team-1",
          projectId: "project-1",
          sessionId: SESSION_ID,
          name: "Provider blind",
          tmuxName: "provider-blind",
          runtimeProfile: { kind: "daytona" },
        } as never,
        3
      )
    );
    const session = await kernel.teamSessions.inspect({
      type: "session.get",
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      sessionId: SESSION_ID,
      actor: ACTOR,
    });
    expect(session?.runtime).toMatchObject({
      kind: "local-tmux",
      isolation: "trusted-shared-host",
      tmuxName: "provider-blind",
    });
    kernel.teamSessions.close();
  });

  it("fails deployment composition closed on Phase-8 claims and private observation keys", async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-hosted-session-"));
    const filename = path.join(directory, "sessions.sqlite");
    const base = hostedProfile();
    const security = {
      hostedRuntimeActivationSource: hostedActivationSource(),
      runtimeCommandAuthorityIssuer: createTestRuntimeCommandAuthorityIssuer(),
      runtimeAuthorizationSnapshotSource: {
        resolve: () => ({
          generation: 1,
          networkPolicyRef: "network-policy:v1",
          networkPolicyDigest: DIGEST_A,
          credentialPolicyRef: "credential-policy:v1",
          credentialPolicyDigest: DIGEST_B,
          effectEnforcerPolicyDigest: DIGEST_C,
        }),
      },
      runtimeEnforcementProofVerifier: (() => true) as SynchronousRuntimeEnforcementProofVerifier,
    };
    expect(() =>
      createTeamSessionKernel({
        filename,
        ...security,
        runtimeProfile: {
          ...base,
          capabilities: { ...base.capabilities, proxyOnlyEgress: true },
        } as never,
      })
    ).toThrow(/Runtime deployment profile is invalid/);

    expect(() =>
      createTeamSessionKernel({
        filename,
        ...security,
        runtimeProfile: base,
      })
    ).toThrow(/observation key provisioning/);
    expect(fs.existsSync(filename)).toBe(false);

    const privateFilename = path.join(directory, "private-observation.sqlite");
    const { privateKey } = generateKeyPairSync("ed25519");
    const privateKernel = createTeamSessionKernel({
      filename: privateFilename,
      ...security,
      runtimeProfile: base,
      hostedRuntimeObservationProvisioner: () => ({
        keyProvisioningRef: "private-observation",
        issuerKeyId: "private-observation",
        publicKeySpkiPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      }),
    });
    await privateKernel.teamSessions.dispatch(
      command({ type: "team.create", teamId: "team-private", name: "T" }, 10)
    );
    await privateKernel.teamSessions.dispatch(
      command(
        {
          type: "project.create",
          teamId: "team-private",
          projectId: "project-private",
          name: "P",
        },
        11
      )
    );
    await expect(
      privateKernel.teamSessions.dispatch(
        command(
          {
            type: "session.start",
            teamId: "team-private",
            projectId: "project-private",
            sessionId: SESSION_ID,
            name: "Reject private key material",
          },
          12
        )
      )
    ).rejects.toMatchObject({ code: "conflict" });
    privateKernel.teamSessions.close();
    const privateDatabase = new Database(privateFilename, { readonly: true });
    try {
      expect(privateDatabase.prepare(`SELECT count(*) AS count FROM sessions`).get()).toEqual({
        count: 0,
      });
    } finally {
      privateDatabase.close();
    }

    const proxyFilename = path.join(directory, "proxy-observation.sqlite");
    const { publicKey: proxyPublicKey } = generateKeyPairSync("ed25519");
    const proxyKernel = createTeamSessionKernel({
      filename: proxyFilename,
      ...security,
      runtimeProfile: base,
      hostedRuntimeObservationProvisioner: () =>
        new Proxy(
          {
            keyProvisioningRef: "proxy-observation",
            issuerKeyId: "proxy-observation",
            publicKeySpkiPem: proxyPublicKey.export({ type: "spki", format: "pem" }).toString(),
          },
          {}
        ),
    });
    await proxyKernel.teamSessions.dispatch(
      command({ type: "team.create", teamId: "team-proxy", name: "T" }, 13)
    );
    await proxyKernel.teamSessions.dispatch(
      command(
        {
          type: "project.create",
          teamId: "team-proxy",
          projectId: "project-proxy",
          name: "P",
        },
        14
      )
    );
    await expect(
      proxyKernel.teamSessions.dispatch(
        command(
          {
            type: "session.start",
            teamId: "team-proxy",
            projectId: "project-proxy",
            sessionId: SESSION_ID,
            name: "Reject proxy registration",
          },
          15
        )
      )
    ).rejects.toMatchObject({ code: "conflict" });
    proxyKernel.teamSessions.close();
    const proxyDatabase = new Database(proxyFilename, { readonly: true });
    try {
      expect(proxyDatabase.prepare(`SELECT count(*) AS count FROM sessions`).get()).toEqual({
        count: 0,
      });
    } finally {
      proxyDatabase.close();
    }

    const reusedFilename = path.join(directory, "reused-observation.sqlite");
    const { publicKey: reusedPublicKey } = generateKeyPairSync("ed25519");
    const reusedKernel = createTeamSessionKernel({
      filename: reusedFilename,
      ...security,
      runtimeProfile: base,
      hostedRuntimeObservationProvisioner: () => ({
        keyProvisioningRef: "reused-observation",
        issuerKeyId: "reused-observation",
        publicKeySpkiPem: reusedPublicKey.export({ type: "spki", format: "pem" }).toString(),
      }),
    });
    await reusedKernel.teamSessions.dispatch(
      command({ type: "team.create", teamId: "team-reuse", name: "T" }, 13)
    );
    await reusedKernel.teamSessions.dispatch(
      command(
        {
          type: "project.create",
          teamId: "team-reuse",
          projectId: "project-reuse",
          name: "P",
        },
        14
      )
    );
    await reusedKernel.teamSessions.dispatch(
      command(
        {
          type: "session.start",
          teamId: "team-reuse",
          projectId: "project-reuse",
          sessionId: SESSION_ID,
          name: "First key owner",
        },
        15
      )
    );
    await expect(
      reusedKernel.teamSessions.dispatch(
        command(
          {
            type: "session.start",
            teamId: "team-reuse",
            projectId: "project-reuse",
            sessionId: STALE_SESSION_ID,
            name: "Reject key reuse",
          },
          16
        )
      )
    ).rejects.toMatchObject({ code: "conflict" });
    reusedKernel.teamSessions.close();
    const reusedDatabase = new Database(reusedFilename, { readonly: true });
    try {
      expect(reusedDatabase.prepare(`SELECT count(*) AS count FROM sessions`).get()).toEqual({
        count: 1,
      });
      expect(
        reusedDatabase
          .prepare(`SELECT count(*) AS count FROM runtime_principal_observation_keys`)
          .get()
      ).toEqual({ count: 1 });
    } finally {
      reusedDatabase.close();
    }
  });

  it("accepts explicit unconfigured limits and the exact Daytona isolation boundaries", () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-hosted-session-"));
    const profile = hostedProfile();
    const unconfigured = { kind: "unconfigured" } as const;
    const maximumRunLimits = {
      wallClock: unconfigured,
      modelTokens: unconfigured,
      modelSpend: unconfigured,
      outboundBytes: unconfigured,
      actionCounts: {
        local: unconfigured,
        "scoped-external": unconfigured,
        protected: unconfigured,
        forbidden: unconfigured,
      },
    } as const;
    const boundaryProfile: Extract<RuntimeDeploymentProfile, { kind: "daytona" }> = {
      ...profile,
      projectCeiling: {
        ...profile.projectCeiling,
        finiteResourceProfile: { cpu: 64, memoryGiB: 512, diskGiB: 4_096 },
        maximumRunLimits,
      },
      isolation: {
        ...profile.isolation,
        network: {
          ...profile.isolation.network,
          mode: "allowlist",
          allowedDestinations: ["cidr:10.0.0.0/8", "cidr:2001:db8::/64", "domain:*.example.com"],
        },
        resources: { cpu: 64, memoryGiB: 512, diskGiB: 4_096, pids: 1_000_000 },
      },
    };
    createTeamSessionKernel({
      filename: path.join(directory, "valid.sqlite"),
      runtimeProfile: boundaryProfile,
      ...hostedSecurity(),
    }).teamSessions.close();

    const invalidProfiles: unknown[] = [
      {
        ...boundaryProfile,
        projectCeiling: {
          ...boundaryProfile.projectCeiling,
          maximumRunLimits: {
            ...maximumRunLimits,
            modelTokens: { kind: "unconfigured", value: 1 },
          },
        },
      },
      {
        ...boundaryProfile,
        projectCeiling: {
          ...boundaryProfile.projectCeiling,
          maximumRunLimits: { ...maximumRunLimits, modelTokens: { kind: "unlimited" } },
        },
      },
      {
        ...boundaryProfile,
        isolation: {
          ...boundaryProfile.isolation,
          resources: { ...boundaryProfile.isolation.resources, cpu: 65 },
        },
      },
      {
        ...boundaryProfile,
        isolation: {
          ...boundaryProfile.isolation,
          resources: { ...boundaryProfile.isolation.resources, memoryGiB: 513 },
        },
      },
      {
        ...boundaryProfile,
        isolation: {
          ...boundaryProfile.isolation,
          resources: { ...boundaryProfile.isolation.resources, diskGiB: 4_097 },
        },
      },
      {
        ...boundaryProfile,
        isolation: {
          ...boundaryProfile.isolation,
          resources: { ...boundaryProfile.isolation.resources, pids: 1_000_001 },
        },
      },
      ...[
        ["cpu", 0],
        ["memoryGiB", 0],
        ["diskGiB", 0],
        ["pids", 0],
      ].map(([resource, value]) => ({
        ...boundaryProfile,
        isolation: {
          ...boundaryProfile.isolation,
          resources: { ...boundaryProfile.isolation.resources, [resource as string]: value },
        },
      })),
      ...[
        "example.com",
        "url:https://example.com",
        " domain:example.com",
        "domain:bad host",
        "domain:bad..example.com",
        "domain:example.com.",
        `domain:${"a".repeat(64)}.example.com`,
        "cidr:999.999.999.999/24",
        "cidr:10.0.0.0/33",
        "cidr:10.0.0.0/01",
        "cidr:2001:db8::/129",
        "cidr:2001:db8::gg/64",
        "cidr:fe80::1%eth0/64",
        `domain:${"a".repeat(247)}`,
      ].map((destination) => ({
        ...boundaryProfile,
        isolation: {
          ...boundaryProfile.isolation,
          network: {
            ...boundaryProfile.isolation.network,
            allowedDestinations: [destination],
          },
        },
      })),
      {
        ...boundaryProfile,
        isolation: {
          ...boundaryProfile.isolation,
          network: {
            ...boundaryProfile.isolation.network,
            allowedDestinations: Array.from(
              { length: 257 },
              (_, index) => `domain:${index}.example.com`
            ),
          },
        },
      },
      {
        ...boundaryProfile,
        isolation: {
          ...boundaryProfile.isolation,
          network: {
            ...boundaryProfile.isolation.network,
            allowedDestinations: ["domain:EXAMPLE.com", "domain:example.com"],
          },
        },
      },
    ];
    invalidProfiles.forEach((runtimeProfile, index) => {
      const filename = path.join(directory!, `invalid-${index}.sqlite`);
      expect(() =>
        createTeamSessionKernel({
          filename,
          runtimeProfile: runtimeProfile as RuntimeDeploymentProfile,
          ...hostedSecurity(),
        })
      ).toThrow(/Runtime deployment profile is invalid/);
      expect(fs.existsSync(filename)).toBe(false);
    });
  });
});

function command(
  input: Record<string, unknown>,
  number: number,
  actor: ActorContext = ACTOR
): SessionCommand {
  return {
    ...input,
    schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
    actor,
    idempotency: { scope: "vitest:hosted", key: `command-${number}` },
  } as SessionCommand;
}

function hostedProfile(): Extract<RuntimeDeploymentProfile, { kind: "daytona" }> {
  return {
    kind: "daytona",
    source: {
      sourceRevision: "source:v1",
      expectedCommitSha: DIGEST_A,
      setupRef: "setup:v1",
    },
    harnessRef: "harness:v1",
    checkpointPolicyRef: "checkpoint:v1",
    adapterConfigurationRef: "daytona-adapter:v1",
    projectCeiling: {
      revision: "hosted-ceiling:v1",
      digest: DIGEST_C,
      allowedModes: ["supervised", "autonomous"],
      yoloEnabled: false,
      finiteResourceProfile: { cpu: 2, memoryGiB: 4, diskGiB: 20 },
      maximumRunLimits: {
        wallClock: { kind: "capped", value: { milliseconds: 60_000 } },
        modelTokens: { kind: "capped", value: 10_000 },
        modelSpend: { kind: "capped", value: { currency: "USD", minorUnits: 1_000 } },
        outboundBytes: { kind: "capped", value: 1_000_000 },
        actionCounts: {
          local: { kind: "capped", value: 1_000 },
          "scoped-external": { kind: "capped", value: 100 },
          protected: { kind: "capped", value: 10 },
          forbidden: { kind: "capped", value: 1 },
        },
      },
      scopedExternalRulesDigest: DIGEST_A,
      isolationPolicyDigest: DIGEST_B,
      networkPolicyDigest: DIGEST_A,
      credentialPolicyDigest: DIGEST_B,
    },
    isolation: {
      isolationPolicyDigest: DIGEST_B,
      publicAccess: false,
      hostMounts: false,
      linkedSandbox: false,
      rootIdentity: false,
      network: { mode: "blocked", policyDigest: DIGEST_A, allowedDestinations: [] },
      resources: { cpu: 2, memoryGiB: 4, diskGiB: 20, pids: 256 },
    },
    capabilities: {
      isolatedExecution: true,
      brokeredCredentials: false,
      proxyOnlyEgress: false,
      checkpoints: true,
      yoloEligible: false,
    },
  };
}

function hostedSecurity() {
  return {
    hostedRuntimeObservationProvisioner: hostedObservationProvisioner(),
    hostedRuntimeActivationSource: hostedActivationSource(),
    runtimeCommandAuthorityIssuer: createTestRuntimeCommandAuthorityIssuer(),
    runtimeAuthorizationSnapshotSource: {
      resolve: ({
        runtimeAuthorizationGeneration,
      }: {
        runtimeAuthorizationGeneration: number;
      }) => ({
        generation: runtimeAuthorizationGeneration,
        networkPolicyRef: "network-policy:v1",
        networkPolicyDigest: DIGEST_A,
        credentialPolicyRef: "credential-policy:v1",
        credentialPolicyDigest: DIGEST_B,
        effectEnforcerPolicyDigest: DIGEST_C,
      }),
    },
    runtimeEnforcementProofVerifier: (() => true) as SynchronousRuntimeEnforcementProofVerifier,
  };
}

function hostedActivationSource() {
  return Object.freeze({
    resolve(query: {
      binding: HostedRuntimeAssignmentPlan["binding"];
      runtimeAuthorizationGeneration: number;
      assignmentPlanDigest: string;
      effectEnforcerPolicyDigest: string;
    }) {
      return Object.freeze({
        version: 1 as const,
        kind: "hosted-runtime.activation" as const,
        binding: query.binding,
        runtimeAuthorizationGeneration: query.runtimeAuthorizationGeneration,
        assignmentPlanDigest: query.assignmentPlanDigest,
        effectEnforcerPolicyDigest: query.effectEnforcerPolicyDigest,
        providerIdentityCommitment: DIGEST_A,
        providerRevision: 1,
        effectManifestBindingDigest: DIGEST_B,
        effectEnforcerSetDigest: DIGEST_C,
      });
    },
  });
}

function hostedObservationProvisioner() {
  let sequence = 0;
  return ({
    binding,
  }: {
    binding: { runtimeAssignmentId: string; runtimeAssignmentGeneration: number };
  }) => {
    sequence += 1;
    const { publicKey } = generateKeyPairSync("ed25519");
    return {
      keyProvisioningRef: `runtime-observation-key:${binding.runtimeAssignmentId}:${binding.runtimeAssignmentGeneration}`,
      issuerKeyId: sequence === 1 ? "runtime-observer:v1" : `runtime-observer:v1:${sequence}`,
      publicKeySpkiPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    };
  };
}

async function enforceRuntimeLifecycle(
  runtimeJournal: ReturnType<typeof createTeamSessionKernel>["runtimeLifecycleJournal"],
  expectedKind: "run.start" | "run.resume",
  nowMs: number
): Promise<void> {
  const workerId = "runtime-lifecycle-worker";
  const [delivery] = await runtimeJournal.claim({
    workerId,
    limit: 1,
    leaseDurationMs: 30_000,
    nowMs,
  });
  if (!delivery || delivery.command.kind !== expectedKind) {
    throw new Error(`missing hosted ${expectedKind} lifecycle command`);
  }
  const requiredEffectEnforcerSetDigest = delivery.command.requiredEffectEnforcerSetDigest;
  if (!requiredEffectEnforcerSetDigest) throw new Error("missing hosted effect-enforcer digest");
  const effectRef = `effect:${delivery.command.commandId}`;
  const enforcementSubjectDigest = digestRuntimeEnforcementSubject({
    version: 1,
    commandId: delivery.command.commandId,
    commandClaimsDigest: delivery.command.authority.claimsDigest,
    binding: delivery.command.binding,
    runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest,
    effectRefCommitment: commitRuntimeEffectRef(effectRef),
    enforcedFence: delivery.command.toRunStateVersion,
  });
  const proofPayload = {
    generation: delivery.command.runtimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest,
    enforcementSubjectDigest,
    acknowledgements: [
      {
        enforcerRef: "test-runtime-enforcer",
        enforcerKind: "runtime" as const,
        acknowledgementDigest: DIGEST_A,
      },
    ],
  };
  const renewal = await runtimeJournal.renew({
    commandId: delivery.command.commandId,
    workerId,
    expectedAttempt: delivery.attempt,
    expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
    leaseDurationMs: 30_000,
    nowMs,
  });
  if (renewal.kind !== "renewed") throw new Error("hosted Run start lease was not renewed");
  await runtimeJournal.complete({
    commandId: delivery.command.commandId,
    workerId,
    expectedAttempt: delivery.attempt,
    expectedLeaseExpiresAtMs: renewal.leaseExpiresAtMs,
    observedAtMs: nowMs,
    outcome: {
      kind: "receipt",
      receipt: {
        commandId: delivery.command.commandId,
        binding: delivery.command.binding,
        runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
        outcome: "enforced",
        effectRef,
        enforcedFence: delivery.command.toRunStateVersion,
        aggregateEnforcementProof: {
          ...proofPayload,
          aggregateProofDigest: digestAggregateEnforcementProof(proofPayload),
        },
      },
    },
  });
}

async function acknowledgeRuntimeDelivery(
  kernel: ReturnType<typeof createTeamSessionKernel>,
  delivery: RuntimeOutboxDelivery,
  key: string
): Promise<void> {
  if (delivery.dispatchMode === "apply") {
    await kernel.teamSessions.markRuntimeOutboxDispatch({
      outboxId: delivery.outboxId,
      workerId: delivery.leaseOwner,
      expectedAttempt: delivery.attempts,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
    });
  }
  await kernel.teamSessions.dispatch({
    type: "runtime.outbox.acknowledge",
    schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
    actor: {
      kind: "system",
      userId: delivery.leaseOwner,
      displayName: "Runtime worker",
    },
    idempotency: { scope: "vitest:hosted-recovery-worker", key },
    outboxId: delivery.outboxId,
    workerId: delivery.leaseOwner,
    expectedAttempt: delivery.attempts,
    expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
  });
}
