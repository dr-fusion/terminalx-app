import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  createTeamSessionKernel,
  type ActorContext,
  type CommandResult,
  type RunPolicyDraft,
  type SessionCommand,
  type TeamSessionKernel,
  type TeamSessions,
} from "@/lib/team-sessions";
import { digestRunPolicyDraft } from "@/lib/team-sessions/run-policy";
import {
  canonicalRuntimeJson,
  digestNonDuplicateRuntimeReceipt,
  type NonDuplicateRuntimeReceipt,
  type RuntimeLifecycleDelivery,
  type RuntimeReceipt,
} from "@/lib/runtime";
import { createTestRuntimeCommandAuthorityIssuer } from "../helpers/runtime-authority";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ALICE: ActorContext = { kind: "human", userId: "alice", displayName: "Alice" };
const RUNTIME: ActorContext = {
  kind: "system",
  userId: "runtime-lifecycle-worker",
  displayName: "Runtime Lifecycle Worker",
};
const unconfigured = { kind: "unconfigured" } as const;

describe("SQLite Runtime lifecycle journal", () => {
  let directory: string;
  let filename: string;
  let kernel: TeamSessionKernel;
  let sessions: TeamSessions;
  let now: number;
  let commandSequence: number;
  let generated: number;

  beforeEach(async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-runtime-journal-"));
    filename = path.join(directory, "team-sessions.sqlite");
    now = 2_000_000_000_000;
    commandSequence = 0;
    generated = 0;
    openKernel();
    await dispatch({ type: "team.create", teamId: TEAM_ID, name: "Acme" });
    await dispatch({
      type: "project.create",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      name: "Terminal X",
    });
    await dispatch({
      type: "session.start",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      sessionId: SESSION_ID,
      name: "Receipt truth",
      tmuxName: "receipt-truth",
      steeringPolicy: "shared",
    });
    const [ensure] = await sessions.claimRuntimeOutbox({
      workerId: RUNTIME.userId,
      limit: 1,
      leaseDurationMs: 30_000,
    });
    if (!ensure) throw new Error("Expected Runtime ensure delivery");
    await dispatch(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: ensure.outboxId,
        workerId: RUNTIME.userId,
        expectedAttempt: ensure.attempts,
      },
      RUNTIME
    );
  });

  afterEach(() => {
    sessions.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function openKernel(): void {
    kernel = createTeamSessionKernel({
      filename,
      clock: () => now,
      idGenerator: () => {
        generated += 1;
        return `00000000-0000-4000-8000-${String(generated).padStart(12, "0")}`;
      },
      runtimeCommandAuthorityIssuer: createTestRuntimeCommandAuthorityIssuer(),
    });
    sessions = kernel.teamSessions;
  }

  function command(input: Record<string, unknown>, actor = ALICE): SessionCommand {
    commandSequence += 1;
    return {
      ...input,
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      idempotency: { scope: "vitest:runtime-journal", key: `command-${commandSequence}` },
      occurredAtMs: now,
    } as SessionCommand;
  }

  async function dispatch(input: Record<string, unknown>, actor = ALICE): Promise<CommandResult> {
    return sessions.dispatch(command(input, actor));
  }

  function policy(): RunPolicyDraft {
    return {
      mode: "autonomous",
      completionPolicy: { kind: "continue-until-all-goals-achieved" },
      scopedExternalPolicyRef: "project-policy:1",
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
  }

  async function requestStart(): Promise<CommandResult> {
    const runPolicy = policy();
    return dispatch({
      type: "run.start",
      sessionId: SESSION_ID,
      expectedSessionRevision: 1,
      initialGoals: [
        {
          goalId: "goal:truth",
          position: 1,
          title: "Prove Runtime truth",
          acceptanceCriteria: ["Only an enforced receipt activates the Run"],
          dependencyGoalIds: [],
        },
      ],
      commit: {
        policy: runPolicy,
        policyDigest: digestRunPolicyDraft(runPolicy),
        expectedProjectCeilingRevision: "local-tmux-ceiling:v1",
        expectedRuntimeAssignmentGeneration: 1,
        expectedSandboxGeneration: 1,
        expectedRuntimeAuthorizationGeneration: 1,
      },
    });
  }

  async function claimStart(leaseDurationMs = 30_000): Promise<RuntimeLifecycleDelivery> {
    const [delivery] = await kernel.runtimeLifecycleJournal.claim({
      workerId: RUNTIME.userId,
      limit: 1,
      leaseDurationMs,
      nowMs: now,
    });
    expect(delivery?.command.kind).toBe("run.start");
    if (!delivery) throw new Error("Expected run.start delivery");
    return delivery;
  }

  function receipt(
    delivery: RuntimeLifecycleDelivery,
    outcome: "accepted" | "enforced" | "rejected" | "quarantined",
    providerText = "provider-effect"
  ): RuntimeReceipt {
    const base = {
      commandId: delivery.command.commandId,
      binding: delivery.command.binding,
      runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
    };
    switch (outcome) {
      case "accepted":
        return { ...base, outcome, effectRef: providerText };
      case "enforced":
        return {
          ...base,
          outcome,
          effectRef: providerText,
          enforcedFence: delivery.command.toRunStateVersion,
        };
      case "rejected":
        return { ...base, outcome, code: "not_ready", safeDetail: providerText };
      case "quarantined":
        return { ...base, outcome, reason: "isolation_failure", effectRef: providerText };
    }
  }

  async function complete(
    delivery: RuntimeLifecycleDelivery,
    outcome: RuntimeReceipt
  ): Promise<void> {
    await kernel.runtimeLifecycleJournal.complete({
      commandId: delivery.command.commandId,
      workerId: RUNTIME.userId,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      observedAtMs: now,
      outcome: { kind: "receipt", receipt: outcome },
    });
  }

  async function runState() {
    return sessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.run-state",
      sessionId: SESSION_ID,
    });
  }

  function readOne<T>(sql: string, ...parameters: Array<string | number>): T {
    const db = new Database(filename, { readonly: true });
    try {
      return db.prepare(sql).get(...parameters) as T;
    } finally {
      db.close();
    }
  }

  it("queues signed start intent and applies lifecycle truth only with an enforced receipt", async () => {
    const started = await requestStart();
    expect(started.data).toMatchObject({
      lifecycle: "starting",
      stateVersion: 1,
      runtimeCommandStatus: "pending",
    });
    expect(await runState()).toMatchObject({
      lifecycle: "starting",
      stateVersion: 1,
      pendingLifecycleOperation: { kind: "start", status: "queued" },
    });

    const delivery = await claimStart();
    expect(delivery).toMatchObject({
      attempt: 1,
      priorDispatchCertainty: "not-dispatched",
      command: {
        kind: "run.start",
        fromRunStateVersion: 1,
        toRunStateVersion: 2,
      },
    });
    await complete(delivery, receipt(delivery, "enforced"));

    expect(await runState()).toMatchObject({
      lifecycle: "active",
      stateVersion: 2,
      pendingLifecycleOperation: null,
    });
    expect(
      readOne<{ status: string }>(
        `SELECT status FROM runtime_run_command_dispatch WHERE command_id = ?`,
        delivery.command.commandId
      )
    ).toEqual({ status: "enforced" });
    expect(
      readOne<{ count: number }>(
        `SELECT COUNT(*) AS count FROM runtime_run_command_effects WHERE command_id = ?`,
        delivery.command.commandId
      )
    ).toEqual({ count: 1 });
    expect(
      readOne<{ count: number }>(
        `SELECT COUNT(*) AS count FROM session_events
         WHERE session_id = ? AND type = 'run.started'`,
        SESSION_ID
      )
    ).toEqual({ count: 1 });
  });

  it("parks accepted work, never reclaims it, and keeps normalized receipt digests consistent", async () => {
    await requestStart();
    const delivery = await claimStart();
    const canary = "CANARY_PRIVATE_KEY_MATERIAL";
    const accepted = receipt(delivery, "accepted", canary);
    await complete(delivery, accepted);

    expect(await runState()).toMatchObject({
      lifecycle: "starting",
      pendingLifecycleOperation: { kind: "start", status: "awaiting-runtime" },
    });
    await expect(
      kernel.runtimeLifecycleJournal.claim({
        workerId: RUNTIME.userId,
        limit: 1,
        leaseDurationMs: 30_000,
        nowMs: now + 1,
      })
    ).resolves.toEqual([]);
    await complete(delivery, accepted);

    const persisted = readOne<{ receipt_json: string; receipt_digest: string }>(
      `SELECT receipt_json, receipt_digest FROM runtime_run_command_receipts
       WHERE command_id = ?`,
      delivery.command.commandId
    );
    expect(persisted.receipt_json).not.toContain(canary);
    expect(persisted.receipt_digest).toBe(
      createHash("sha256")
        .update(canonicalRuntimeJson(JSON.parse(persisted.receipt_json)), "utf8")
        .digest("hex")
    );
  });

  it("rejects hostile certainty downgrades and terminalizes a proven pre-dispatch failure", async () => {
    await requestStart();
    const delivery = await claimStart();
    await expect(
      kernel.runtimeLifecycleJournal.complete({
        commandId: delivery.command.commandId,
        workerId: RUNTIME.userId,
        expectedAttempt: delivery.attempt,
        expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
        observedAtMs: now,
        outcome: {
          kind: "failure",
          code: "runtime_command_failed",
          dispatchCertainty: "not-dispatched",
        },
      })
    ).rejects.toMatchObject({ code: "invalid_input" });

    await kernel.runtimeLifecycleJournal.complete({
      commandId: delivery.command.commandId,
      workerId: RUNTIME.userId,
      expectedAttempt: delivery.attempt,
      expectedLeaseExpiresAtMs: delivery.leaseExpiresAtMs,
      observedAtMs: now,
      outcome: {
        kind: "failure",
        code: "invalid_input",
        dispatchCertainty: "not-dispatched",
      },
    });
    expect(await runState()).toMatchObject({
      lifecycle: "failed",
      stateVersion: 2,
      pendingLifecycleOperation: null,
    });
  });

  it("normalizes rejected provider text and fails the pending start atomically", async () => {
    await requestStart();
    const delivery = await claimStart();
    const canary = "CANARY_SLACK_TOKEN";
    await complete(delivery, receipt(delivery, "rejected", canary));

    expect(await runState()).toMatchObject({ lifecycle: "failed", stateVersion: 2 });
    const persisted = readOne<{ receipt_json: string; payload_json: string }>(
      `SELECT receipt.receipt_json, event.payload_json
       FROM runtime_run_command_receipts receipt
       JOIN runtime_run_commands command ON command.id = receipt.command_id
       JOIN session_events event ON event.session_id = command.session_id
       WHERE receipt.command_id = ? AND event.type = 'run.runtime-command.rejected'
       ORDER BY event.sequence DESC LIMIT 1`,
      delivery.command.commandId
    );
    expect(persisted.receipt_json).not.toContain(canary);
    expect(persisted.payload_json).not.toContain(canary);
    expect(JSON.parse(persisted.payload_json)).toMatchObject({ code: "not_ready" });
  });

  it("contains a quarantined start and never reports it active", async () => {
    await requestStart();
    const delivery = await claimStart();
    await complete(delivery, receipt(delivery, "quarantined"));

    expect(await runState()).toMatchObject({
      lifecycle: "failed",
      stateVersion: 2,
      sandboxState: "quarantined",
    });
    expect(
      readOne<{ runtime_authorization_state: string; assignment_status: string }>(
        `SELECT session.runtime_authorization_state,
                assignment.status AS assignment_status
         FROM sessions session
         JOIN runtime_assignments assignment ON assignment.session_id = session.id
         WHERE session.id = ?`,
        SESSION_ID
      )
    ).toEqual({
      runtime_authorization_state: "quarantined",
      assignment_status: "quarantined",
    });
  });

  it("contains stale enforced effects and leaves them explicitly compensating", async () => {
    await requestStart();
    const delivery = await claimStart();
    const db = new Database(filename);
    try {
      db.prepare(
        `UPDATE runtime_assignments SET status = 'recovering'
         WHERE id = ? AND status = 'ready'`
      ).run(delivery.command.binding.runtimeAssignmentId);
    } finally {
      db.close();
    }

    await complete(delivery, receipt(delivery, "enforced"));
    expect(await runState()).toMatchObject({
      lifecycle: "starting",
      stateVersion: 1,
      sandboxState: "quarantined",
      pendingLifecycleOperation: { kind: "start", status: "compensating" },
    });
    expect(
      readOne<{ status: string }>(
        `SELECT status FROM runtime_run_command_dispatch WHERE command_id = ?`,
        delivery.command.commandId
      )
    ).toEqual({ status: "compensating" });
    await expect(
      kernel.runtimeLifecycleJournal.claim({
        workerId: "replacement-worker",
        limit: 1,
        leaseDurationMs: 30_000,
        nowMs: now + 1,
      })
    ).resolves.toEqual([]);
  });

  it("rejects a duplicate whose original receipt is bound to another command and tenant", async () => {
    await requestStart();
    const delivery = await claimStart();
    const forgedOriginal = {
      commandId: "another-command",
      binding: {
        ...delivery.command.binding,
        teamId: "attacker-team",
        projectId: "attacker-project",
      },
      runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
      outcome: "enforced",
      effectRef: "forged-effect",
      enforcedFence: delivery.command.toRunStateVersion,
    } as const satisfies NonDuplicateRuntimeReceipt;
    const duplicate = {
      commandId: delivery.command.commandId,
      binding: delivery.command.binding,
      runtimeAuthorizationGeneration: delivery.command.runtimeAuthorizationGeneration,
      outcome: "duplicate",
      originalReceipt: forgedOriginal,
      originalReceiptDigest: digestNonDuplicateRuntimeReceipt(forgedOriginal),
    } as const satisfies RuntimeReceipt;

    await expect(complete(delivery, duplicate)).rejects.toMatchObject({ code: "invalid_input" });
    await expect(runState()).resolves.toMatchObject({
      lifecycle: "starting",
      stateVersion: 1,
      pendingLifecycleOperation: { kind: "start", status: "queued" },
    });
    expect(
      readOne<{ receipts: number; effects: number }>(
        `SELECT
           (SELECT COUNT(*) FROM runtime_run_command_receipts WHERE command_id = ?) AS receipts,
           (SELECT COUNT(*) FROM runtime_run_command_effects WHERE command_id = ?) AS effects`,
        delivery.command.commandId,
        delivery.command.commandId
      )
    ).toEqual({ receipts: 0, effects: 0 });
  });

  it("reconstructs pending work after restart and parks an expired lease as uncertain", async () => {
    await requestStart();
    sessions.close();
    openKernel();
    const delivery = await claimStart(1_000);
    const revisionBefore = (
      await sessions.inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: ALICE,
        type: "session.get",
        sessionId: SESSION_ID,
      })
    )?.runStateRevision;

    now = delivery.leaseExpiresAtMs;
    await kernel.runtimeLifecycleJournal.reconcile({ nowMs: now });
    expect(await runState()).toMatchObject({
      lifecycle: "starting",
      pendingLifecycleOperation: { kind: "start", status: "awaiting-runtime" },
    });
    const session = await sessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.get",
      sessionId: SESSION_ID,
    });
    expect(session?.runStateRevision).toBe((revisionBefore ?? 0) + 1);
    await expect(
      kernel.runtimeLifecycleJournal.claim({
        workerId: "replacement-worker",
        limit: 1,
        leaseDurationMs: 30_000,
        nowMs: now,
      })
    ).resolves.toEqual([]);
  });
});
