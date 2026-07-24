import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ASSIGNMENT_ID = "44444444-4444-4444-8444-444444444444";
const OTHER_SESSION_ID = "55555555-5555-4555-8555-555555555555";
const OTHER_ASSIGNMENT_ID = "66666666-6666-4666-8666-666666666666";

describe("Team Session Agent Run schema", () => {
  let directory: string;
  let filename: string;
  let database: TeamSessionDatabase | undefined;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-agent-run-schema-"));
    filename = path.join(directory, "team-sessions.sqlite");
  });

  afterEach(() => {
    database?.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("initializes the portable Agent Run record set and Runtime command journal at schema v5", () => {
    database = openTeamSessionDatabase({ filename });

    expect(database.db.pragma("user_version", { simple: true })).toBe(5);
    const tables = database.db
      .prepare(
        `SELECT name FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name`
      )
      .all() as Array<{ name: string }>;
    expect(tables.map(({ name }) => name)).toEqual(
      expect.arrayContaining([
        "runtime_assignments",
        "runtime_authorization_epochs",
        "agent_runs",
        "run_policy_revisions",
        "goal_sets",
        "goals",
        "goal_evidence",
        "attention_requests",
        "action_manifests",
        "approval_requests",
        "action_grants",
        "action_grant_states",
        "grant_reviews",
        "runtime_run_commands",
        "runtime_run_command_dispatch",
        "runtime_run_command_receipts",
        "runtime_run_command_effects",
      ])
    );
    const sessionColumns = database.db.prepare("PRAGMA table_info(sessions)").all() as Array<{
      name: string;
    }>;
    expect(sessionColumns.map(({ name }) => name)).toContain("run_state_revision");
    const runColumns = database.db.prepare("PRAGMA table_info(agent_runs)").all() as Array<{
      name: string;
    }>;
    expect(runColumns.map(({ name }) => name)).toContain("start_command_id");
    const dispatchColumns = database.db
      .prepare("PRAGMA table_info(runtime_run_command_dispatch)")
      .all() as Array<{ name: string }>;
    expect(dispatchColumns.map(({ name }) => name)).toContain("available_at_ms");
    expect(
      database.db
        .prepare(
          `SELECT sql FROM sqlite_schema
           WHERE type = 'index' AND name = 'runtime_run_command_dispatch_claimable'`
        )
        .get()
    ).toMatchObject({ sql: expect.stringContaining("available_at_ms") });
    expect(
      database.db
        .prepare(
          `SELECT sql FROM sqlite_schema
           WHERE type = 'index' AND name = 'one_unresolved_runtime_run_command_per_run'`
        )
        .get()
    ).toMatchObject({ sql: expect.stringContaining("'compensating'") });
    const commandTable = database.db
      .prepare(
        `SELECT sql FROM sqlite_schema
         WHERE type = 'table' AND name = 'runtime_run_commands'`
      )
      .get() as { sql: string };
    expect(commandTable.sql).toContain("operation <> 'run.start'");
    expect(commandTable.sql).toContain("expected_run_state_version = 1");
    expect(commandTable.sql).toContain("target_run_state_version = 2");
  });

  it("migrates a genuine v2 Session schema through v3, v4, and v5 in one open", () => {
    createAgentRunSchemaV2Fixture(filename);

    database = openTeamSessionDatabase({ filename });

    expect(database.db.pragma("user_version", { simple: true })).toBe(5);
    expect(
      database.db
        .prepare(`SELECT name FROM sqlite_schema WHERE type = 'table' AND name = 'agent_runs'`)
        .get()
    ).toEqual({ name: "agent_runs" });
    seedSessionAndAssignment(database.db);
    expect(() => insertDanglingRun(database!.db, "run-dangling", "active")).toThrow(
      /FOREIGN KEY constraint failed/
    );
    expect(() => insertRun(database!.db, "run-1", "active")).not.toThrow();
    expect(
      database.db
        .prepare(`SELECT runtime_kind FROM runtime_assignments WHERE id = ?`)
        .get(ASSIGNMENT_ID)
    ).toEqual({ runtime_kind: "local-tmux" });
    expect(() =>
      database!.db.prepare(`UPDATE sessions SET tmux_name = 'mutated' WHERE id = ?`).run(SESSION_ID)
    ).toThrow(/Session Runtime configuration is immutable/);
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
  });

  it("allows only one mutable Run per Session while retaining terminal history", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);

    insertRun(database.db, "run-1", "active");
    expect(() => insertRun(database!.db, "run-2", "paused")).toThrow(/UNIQUE constraint failed/);

    database.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = 'completed', state_version = 2, terminal_at_ms = ?, updated_at_ms = ?
         WHERE id = 'run-1'`
      )
      .run(30, 30);
    expect(() => insertRun(database!.db, "run-2", "paused")).not.toThrow();
  });

  it("requires both current Run heads to resolve to snapshots owned by that Run", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");

    expect(() =>
      database!.db
        .prepare(`UPDATE agent_runs SET current_policy_revision = 2 WHERE id = 'run-1'`)
        .run()
    ).toThrow(/FOREIGN KEY constraint failed/);
    expect(() =>
      database!.db
        .prepare(`UPDATE agent_runs SET current_goal_set_revision = 2 WHERE id = 'run-1'`)
        .run()
    ).toThrow(/FOREIGN KEY constraint failed/);
  });

  it("keeps policy revisions immutable and rejects omitted Run-limit discriminants", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");

    expect(() =>
      insertPolicy(database!.db, {
        ...completeLimits(),
        modelTokens: undefined,
      })
    ).toThrow(/CHECK constraint failed/);

    insertPolicy(database.db, completeLimits());
    expect(() =>
      database!.db
        .prepare(`UPDATE run_policy_revisions SET mode = 'supervised' WHERE agent_run_id = 'run-1'`)
        .run()
    ).toThrow(/Run policy revisions are immutable/);
  });

  it("keeps one-based Goal snapshots immutable and aligns evidence review state", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");

    expect(() =>
      database!.db
        .prepare(
          `INSERT INTO goal_sets
             (goal_set_id, agent_run_id, revision, previous_revision, digest, created_at_ms)
           VALUES ('goal-set-1', 'run-1', 2, NULL, ?, 21)`
        )
        .run(digestFor("invalid-goal-set-revision"))
    ).toThrow(/CHECK constraint failed/);
    expect(() =>
      database!.db
        .prepare(
          `INSERT INTO goal_sets
             (goal_set_id, agent_run_id, revision, previous_revision, digest, created_at_ms)
           VALUES ('different-goal-set', 'run-1', 2, 1, ?, 21)`
        )
        .run(digestFor("different-goal-set"))
    ).toThrow(/FOREIGN KEY constraint failed/);

    expect(() => insertGoal(database!.db, 0, "Invalid position")).toThrow(
      /CHECK constraint failed/
    );
    expect(() => insertGoal(database!.db, 1, "x".repeat(1_001))).toThrow(/CHECK constraint failed/);
    insertGoal(database.db, 1, "x".repeat(1_000));

    expect(() =>
      database!.db
        .prepare(`UPDATE goal_sets SET digest = ? WHERE agent_run_id = 'run-1'`)
        .run("c".repeat(64))
    ).toThrow(/Goal Set revisions are immutable/);
    expect(() =>
      database!.db.prepare(`DELETE FROM goal_sets WHERE agent_run_id = 'run-1'`).run()
    ).toThrow(/Goal Set revisions are immutable/);
    expect(() =>
      database!.db.prepare(`UPDATE goals SET title = 'Changed' WHERE goal_id = 'goal-1'`).run()
    ).toThrow(/Goal snapshots are immutable/);
    expect(() => database!.db.prepare(`DELETE FROM goals WHERE goal_id = 'goal-1'`).run()).toThrow(
      /Goal snapshots are immutable/
    );

    expect(() => insertEvidence(database!.db, "evidence-invalid-1", "proposed", 40)).toThrow(
      /CHECK constraint failed/
    );
    expect(() => insertEvidence(database!.db, "evidence-invalid-2", "validated")).toThrow(
      /CHECK constraint failed/
    );
    expect(() => insertEvidence(database!.db, "evidence-valid", "validated", 40)).not.toThrow();
  });

  it("rejects Goal evidence bound to another Run or a nonexistent Goal version", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");
    insertGoal(database.db, 1, "Goal");
    insertTerminalRun(database.db, "run-2");

    expect(() =>
      insertEvidenceBinding(database!.db, {
        evidenceId: "evidence-cross-run",
        agentRunId: "run-2",
        goalVersion: 1,
      })
    ).toThrow(/FOREIGN KEY constraint failed/);
    expect(() =>
      insertEvidenceBinding(database!.db, {
        evidenceId: "evidence-fake-version",
        agentRunId: "run-1",
        goalVersion: 999,
      })
    ).toThrow(/FOREIGN KEY constraint failed/);
  });

  it("rejects Run policies bound to another Session or a missing Goal Set", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    seedOtherSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");

    expect(() =>
      insertPolicy(database!.db, completeLimits(), {
        assignmentId: OTHER_ASSIGNMENT_ID,
        sandboxId: "sandbox-2",
        runtimePrincipalId: "principal-2",
      })
    ).toThrow(/FOREIGN KEY constraint failed/);
    expect(() =>
      insertPolicy(database!.db, completeLimits(), { goalSetId: "missing-goal-set" })
    ).toThrow(/FOREIGN KEY constraint failed/);
  });

  it("permits checkpointing and recovering as current Runtime assignment states", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);

    expect(() =>
      database!.db
        .prepare(`UPDATE runtime_assignments SET status = 'checkpointing' WHERE id = ?`)
        .run(ASSIGNMENT_ID)
    ).not.toThrow();
    expect(() =>
      database!.db
        .prepare(`UPDATE runtime_assignments SET status = 'recovering' WHERE id = ?`)
        .run(ASSIGNMENT_ID)
    ).not.toThrow();
  });

  it("keeps Runtime identity immutable and authorization heads monotonic", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);

    expect(() =>
      database!.db
        .prepare(`UPDATE runtime_assignments SET runtime_kind = 'daytona' WHERE id = ?`)
        .run(ASSIGNMENT_ID)
    ).toThrow(/Runtime Assignment identity is immutable/);
    database.db
      .prepare(
        `UPDATE sessions
         SET runtime_authorization_generation = 2, runtime_authorization_state = 'pending'
         WHERE id = ?`
      )
      .run(SESSION_ID);
    expect(() =>
      database!.db
        .prepare(
          `UPDATE sessions
           SET runtime_authorization_generation = 1, runtime_authorization_state = 'enforced'
           WHERE id = ?`
        )
        .run(SESSION_ID)
    ).toThrow(/Invalid Session Runtime authorization transition/);
    database.db
      .prepare(
        `UPDATE runtime_assignments
         SET runtime_authorization_generation = 2, status = 'recovering'
         WHERE id = ?`
      )
      .run(ASSIGNMENT_ID);
    expect(() =>
      database!.db
        .prepare(`UPDATE runtime_assignments SET runtime_authorization_generation = 1 WHERE id = ?`)
        .run(ASSIGNMENT_ID)
    ).toThrow(/cannot move backwards/);
  });

  it("keeps approvals and grants out of local/forbidden paths and Run-scopes only external work", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");
    insertManifest(database.db);

    expect(() => insertApproval(database!.db, "local")).toThrow(/CHECK constraint failed/);
    expect(() => insertApproval(database!.db, "forbidden")).toThrow(/CHECK constraint failed/);
    insertApproval(database.db, "scoped-external");
    insertApproval(database.db, "scoped-external", {
      approvalId: "approval-run",
      subjectKind: "run-pattern",
    });

    expect(() => insertGrant(database!.db, "local", "once")).toThrow(
      /CHECK constraint failed|does not match/
    );
    expect(() =>
      insertGrant(database!.db, "protected", "run", { approvalId: "approval-run" })
    ).toThrow(/CHECK constraint failed|does not match/);
    expect(() =>
      insertGrant(database!.db, "scoped-external", "run", { approvalId: "approval-run" })
    ).not.toThrow();
  });

  it("rejects approvals for a fake digest or a manifest owned by another Run", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");
    insertManifest(database.db);
    insertTerminalRun(database.db, "run-2");
    insertManifest(database.db, {
      manifestId: "manifest-2",
      agentRunId: "run-2",
      digest: digestFor("manifest-2"),
      effectIdempotencyKey: "effect-2",
    });

    expect(() =>
      insertApproval(database!.db, "scoped-external", {
        approvalId: "approval-fake-digest",
        manifestDigest: digestFor("fake-manifest"),
      })
    ).toThrow(/FOREIGN KEY constraint failed|action manifest/);
    expect(() =>
      insertApproval(database!.db, "scoped-external", {
        approvalId: "approval-cross-run",
        manifestId: "manifest-2",
        manifestDigest: digestFor("manifest-2"),
      })
    ).toThrow(/FOREIGN KEY constraint failed|action manifest/);
  });

  it("rejects an Action Grant backed by a denied Approval version", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");
    insertManifest(database.db);
    insertApproval(database.db, "scoped-external", {
      approvalId: "approval-denied",
      status: "denied",
    });

    expect(() =>
      insertGrant(database!.db, "scoped-external", "once", {
        approvalId: "approval-denied",
        grantId: "grant-denied",
      })
    ).toThrow(/FOREIGN KEY constraint failed|approved request/);
  });

  it("issues at most one grant from an exact Approval version", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");
    insertManifest(database.db);
    insertApproval(database.db, "scoped-external");
    insertGrant(database.db, "scoped-external", "once");

    expect(() =>
      insertGrant(database!.db, "scoped-external", "once", { grantId: "grant-duplicate" })
    ).toThrow(/UNIQUE constraint failed/);
  });

  it("persists a versioned Grant Review with revoke-all as its safe default", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");

    expect(() => insertGrantReview(database!.db, "keep-all")).toThrow(/CHECK constraint failed/);
    expect(() => insertGrantReview(database!.db, "revoke-all")).not.toThrow();
    expect(
      database.db
        .prepare(`SELECT safe_default, status FROM grant_reviews WHERE id = 'grant-review-1'`)
        .get()
    ).toEqual({ safe_default: "revoke-all", status: "open" });
  });

  it("migrates a v3-equivalent database additively without fabricating Runtime truth", () => {
    const beforeMigration = createRuntimeRunSchemaV3Fixture(filename);

    database = openTeamSessionDatabase({ filename });

    expect(database.db.pragma("user_version", { simple: true })).toBe(5);
    expect(
      database.db
        .prepare(`SELECT name FROM sqlite_schema WHERE type = 'table' AND name = ?`)
        .get("runtime_run_commands")
    ).toEqual({ name: "runtime_run_commands" });
    expect(database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_run_commands`).get()).toEqual(
      { count: 0 }
    );
    const migratedOutbox = database.db
      .prepare(`SELECT * FROM runtime_outbox WHERE id = 'legacy-runtime-outbox-1'`)
      .get();
    expect(migratedOutbox).toEqual(beforeMigration.outbox);
    expect(migratedOutbox).toMatchObject({
      payload_json: '{ "runtime": "legacy", "generation": 1 }',
      status: "pending",
      attempts: 3,
    });
    expect(
      database.db
        .prepare(`SELECT * FROM session_events WHERE event_id = 'event:legacy-runtime-outbox'`)
        .get()
    ).toEqual(beforeMigration.sourceEvent);
    expect(database.db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(SESSION_ID)).toEqual(
      beforeMigration.session
    );
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
  });

  it("migrates a genuinely populated v4 Runtime journal to v5 without losing truth", () => {
    const beforeMigration = createPopulatedRuntimeRunSchemaV4Fixture(filename);

    database = openTeamSessionDatabase({ filename });

    expect(database.db.pragma("user_version", { simple: true })).toBe(5);
    expect(
      database.db
        .prepare(`SELECT * FROM runtime_run_commands WHERE id = ?`)
        .get("runtime-command-1")
    ).toEqual(beforeMigration.command);
    expect(
      database.db
        .prepare(`SELECT * FROM runtime_run_command_receipts WHERE id = ?`)
        .get("receipt-1")
    ).toEqual(beforeMigration.receipt);
    expect(
      database.db
        .prepare(`SELECT * FROM runtime_run_command_effects WHERE command_id = ?`)
        .get("runtime-command-1")
    ).toEqual(beforeMigration.effect);
    expect(database.db.prepare(`SELECT * FROM agent_runs WHERE id = 'run-1'`).get()).toMatchObject({
      ...beforeMigration.run,
      start_command_id: null,
    });
    expect(
      database.db
        .prepare(`SELECT * FROM runtime_run_command_dispatch WHERE command_id = ?`)
        .get("runtime-command-1")
    ).toMatchObject({ ...beforeMigration.dispatch, available_at_ms: 120 });
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
  });

  it.each([
    ["pending", "pending", 100, null, 0],
    ["processing-live", "awaiting-receipt", 101, "migration_dispatch_uncertain", 0],
    ["processing-expired", "awaiting-receipt", 101, "migration_dispatch_uncertain", 0],
    ["retried-pending", "awaiting-receipt", 102, "migration_dispatch_uncertain", 0],
    ["awaiting", "awaiting-receipt", 110, null, 0],
    ["accepted", "awaiting-receipt", 110, null, 1],
  ] as const)(
    "migrates a populated v4 %s dispatch without inventing redispatch certainty",
    (fixtureState, expectedStatus, expectedAvailableAtMs, expectedSafeCode, expectedReceipts) => {
      createRuntimeRunSchemaV4DispatchFixture(filename, fixtureState);

      database = openTeamSessionDatabase({ filename });

      expect(database.db.pragma("user_version", { simple: true })).toBe(5);
      expect(
        database.db
          .prepare(
            `SELECT status, available_at_ms, lease_owner, lease_expires_at_ms,
                    last_safe_error_code
             FROM runtime_run_command_dispatch WHERE command_id = 'runtime-command-1'`
          )
          .get()
      ).toEqual({
        status: expectedStatus,
        available_at_ms: expectedAvailableAtMs,
        lease_owner: null,
        lease_expires_at_ms: null,
        last_safe_error_code: expectedSafeCode,
      });
      expect(
        database.db
          .prepare(
            `SELECT COUNT(*) AS count FROM runtime_run_command_receipts
             WHERE command_id = 'runtime-command-1'`
          )
          .get()
      ).toEqual({ count: expectedReceipts });
      expect(database.db.pragma("foreign_key_check")).toEqual([]);
      expect(database.db.pragma("quick_check", { simple: true })).toBe("ok");
    }
  );

  it("fences starting Runs behind their exact durable start effect", () => {
    database = openTeamSessionDatabase({ filename });
    seedStartingRuntimeRunCommand(database.db);

    expect(
      database.db
        .prepare(
          `SELECT lifecycle, state_version, start_command_id FROM agent_runs WHERE id = 'run-1'`
        )
        .get()
    ).toEqual({
      lifecycle: "starting",
      state_version: 1,
      start_command_id: "runtime-command-start",
    });
    expect(() =>
      database!.db
        .prepare(
          `UPDATE agent_runs
           SET lifecycle = 'active', state_version = 2, updated_at_ms = 115
           WHERE id = 'run-1'`
        )
        .run()
    ).toThrow(/lacks an enforced effect/);
    expect(() =>
      database!.db
        .prepare(`UPDATE agent_runs SET start_command_id = 'different-command' WHERE id = 'run-1'`)
        .run()
    ).toThrow(/start command identity is immutable/);

    claimRuntimeRunDispatch(database.db, "runtime-command-start");
    insertRuntimeRunReceipt(database.db, { commandId: "runtime-command-start" });
    insertRuntimeRequestEvent(database.db, 2, "event:start-enforced", {
      commandId: "runtime-command-start",
      type: "run.started",
      operation: "run.start",
    });
    insertRuntimeRunEffect(database.db, digestFor("start-effect"), {
      commandId: "runtime-command-start",
    });
    expect(() =>
      database!.db
        .prepare(
          `UPDATE agent_runs
           SET lifecycle = 'active', state_version = 2, updated_at_ms = 115
           WHERE id = 'run-1'`
        )
        .run()
    ).not.toThrow();
    expect(() =>
      terminalizeRuntimeRunDispatch(database!.db, 120, "enforced", "runtime-command-start")
    ).not.toThrow();
  });

  it("keeps emergency quarantine reachable and rejects a late start effect", () => {
    database = openTeamSessionDatabase({ filename });
    seedStartingRuntimeRunCommand(database.db);
    claimRuntimeRunDispatch(database.db, "runtime-command-start");

    database.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = 'pausing', state_version = 2, updated_at_ms = 105
         WHERE id = 'run-1'`
      )
      .run();
    insertRuntimeRunReceipt(database.db, { commandId: "runtime-command-start" });
    insertRuntimeRequestEvent(database.db, 2, "event:late-start-enforced", {
      commandId: "runtime-command-start",
      type: "run.started",
      operation: "run.start",
    });
    expect(() =>
      insertRuntimeRunEffect(database!.db, digestFor("late-start-effect"), {
        commandId: "runtime-command-start",
      })
    ).toThrow(/does not match current dispatch and Run state/);
    expect(() =>
      database!.db
        .prepare(
          `UPDATE agent_runs
           SET lifecycle = 'emergency-stopped', state_version = 3,
               terminal_at_ms = 110, updated_at_ms = 110
           WHERE id = 'run-1'`
        )
        .run()
    ).not.toThrow();
  });

  it.each(["rejected", "quarantined"] as const)(
    "allows a proven terminal %s start to fail its Run",
    (outcome) => {
      database = openTeamSessionDatabase({ filename });
      seedStartingRuntimeRunCommand(database.db);
      claimRuntimeRunDispatch(database.db, "runtime-command-start");
      insertRuntimeRunReceipt(database.db, {
        commandId: "runtime-command-start",
        outcome,
      });

      expect(() =>
        database!.db
          .prepare(
            `UPDATE agent_runs
             SET lifecycle = 'failed', state_version = 2, terminal_at_ms = 120,
                 updated_at_ms = 120
             WHERE id = 'run-1'`
          )
          .run()
      ).toThrow(/lacks a terminal dispatch proof/);
      terminalizeRuntimeRunDispatch(database.db, 120, outcome, "runtime-command-start");
      expect(() =>
        database!.db
          .prepare(
            `UPDATE agent_runs
             SET lifecycle = 'failed', state_version = 2, terminal_at_ms = 121,
                 updated_at_ms = 121
             WHERE id = 'run-1'`
          )
          .run()
      ).not.toThrow();
    }
  );

  it("allows a safe permanent pre-dispatch start failure but not an unproven one", () => {
    database = openTeamSessionDatabase({ filename });
    seedStartingRuntimeRunCommand(database.db);

    const failWithoutSafeProof = database.db.transaction(() => {
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'failed', terminal_at_ms = 109, updated_at_ms = 109
           WHERE command_id = 'runtime-command-start'`
        )
        .run();
      database!.db
        .prepare(
          `UPDATE agent_runs
           SET lifecycle = 'failed', state_version = 2, terminal_at_ms = 109,
               updated_at_ms = 109
           WHERE id = 'run-1'`
        )
        .run();
    });
    expect(() => failWithoutSafeProof()).toThrow(
      /Invalid Runtime Run command dispatch transition|lacks a terminal dispatch proof/
    );

    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'failed', last_safe_error_code = 'invalid_authority',
             terminal_at_ms = 110, updated_at_ms = 110
         WHERE command_id = 'runtime-command-start'`
      )
      .run();
    expect(() =>
      database!.db
        .prepare(
          `UPDATE agent_runs
           SET lifecycle = 'failed', state_version = 2, terminal_at_ms = 111,
               updated_at_ms = 111
           WHERE id = 'run-1'`
        )
        .run()
    ).not.toThrow();
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'pending', terminal_at_ms = NULL, updated_at_ms = 112
           WHERE command_id = 'runtime-command-start'`
        )
        .run()
    ).toThrow(/Invalid Runtime Run command dispatch transition/);
  });

  it("enforces due-time claims and treats an expired dispatch lease as uncertain", () => {
    database = openTeamSessionDatabase({ filename });
    seedRuntimeRunCommand(database.db);

    expect(() => claimRuntimeRunDispatch(database!.db, "runtime-command-1", 99)).toThrow(
      /Invalid Runtime Run command dispatch transition/
    );
    claimRuntimeRunDispatch(database.db, "runtime-command-1");
    for (const unsafeCode of [null, "arbitrary", "runtime_command_failed"] as const) {
      expect(() =>
        database!.db
          .prepare(
            `UPDATE runtime_run_command_dispatch
             SET status = 'pending', available_at_ms = 150,
                 lease_owner = NULL, lease_expires_at_ms = NULL,
                 last_safe_error_code = ?, updated_at_ms = 102
             WHERE command_id = 'runtime-command-1'`
          )
          .run(unsafeCode)
      ).toThrow(/Invalid Runtime Run command dispatch transition/);
    }
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET lease_owner = 'worker-2', lease_expires_at_ms = 220, updated_at_ms = 102
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime Run command dispatch transition/);
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET attempts = 2, lease_owner = 'worker-2', lease_expires_at_ms = 300,
               updated_at_ms = 199
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime Run command dispatch transition/);
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET attempts = 2, lease_owner = 'worker-2', lease_expires_at_ms = 300,
               updated_at_ms = 200
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime Run command dispatch transition/);

    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'awaiting-receipt', lease_owner = NULL, lease_expires_at_ms = NULL,
             available_at_ms = 210, updated_at_ms = 200
         WHERE command_id = 'runtime-command-1'`
      )
      .run();
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'processing', attempts = 2, lease_owner = 'worker-2',
               lease_expires_at_ms = 300, updated_at_ms = 210
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime Run command dispatch transition/);
  });

  it("retains a stale enforced receipt in a non-claimable compensating state", () => {
    database = openTeamSessionDatabase({ filename });
    seedRuntimeRunCommand(database.db);
    claimRuntimeRunDispatch(database.db, "runtime-command-1");
    database.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = 'pausing', state_version = 2, updated_at_ms = 105
         WHERE id = 'run-1'`
      )
      .run();

    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'compensating', lease_owner = NULL, lease_expires_at_ms = NULL,
               updated_at_ms = 110
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime Run command dispatch transition/);
    insertRuntimeRunReceipt(database.db);
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'compensating', lease_owner = NULL, lease_expires_at_ms = NULL,
               updated_at_ms = 110
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).not.toThrow();
    expect(
      database.db
        .prepare(
          `SELECT status, attempts, terminal_at_ms
           FROM runtime_run_command_dispatch WHERE command_id = 'runtime-command-1'`
        )
        .get()
    ).toEqual({ status: "compensating", attempts: 1, terminal_at_ms: null });
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'pending', available_at_ms = 111, updated_at_ms = 111
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime Run command dispatch transition/);
  });

  it("binds immutable Runtime Run commands to one exact Run snapshot", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");
    insertRuntimeRequestEvent(database.db, 1, "event:pause-requested");

    expect(() =>
      insertRuntimeRunCommand(database!.db, {
        sandboxGeneration: 2,
      })
    ).toThrow(
      /FOREIGN KEY constraint failed|JSON scope does not match|does not match current Run state/
    );
    expect(() =>
      insertRuntimeRunCommand(database!.db, {
        operation: "run.pause",
        targetLifecycle: "active",
      })
    ).toThrow(/CHECK constraint failed|source event does not match/);
    expect(() =>
      insertRuntimeRunCommand(database!.db, {
        commandDigest: "A".repeat(64),
      })
    ).toThrow(/CHECK constraint failed/);
    expect(() =>
      insertRuntimeRunCommand(database!.db, {
        // v5 accepts start only for an exact-bound starting Run and policy snapshot.
        operation: "run.start",
        targetLifecycle: "active",
      })
    ).toThrow(
      /CHECK constraint failed|does not match current Run state|source event does not match/
    );
    expect(() => insertRuntimeRunCommand(database!.db, { omitPerKindField: true })).toThrow(
      /CHECK constraint failed/
    );
    expect(() =>
      insertRuntimeRunCommand(database!.db, {
        commandJson: "{}",
      })
    ).toThrow(/CHECK constraint failed|JSON scope does not match|source event does not match/);
    expect(() =>
      insertRuntimeRunCommand(database!.db, {
        targetRunStateVersion: 3,
      })
    ).toThrow(/CHECK constraint failed|source event does not match/);
    expect(() =>
      insertRuntimeRunCommand(database!.db, { projectCeilingRevision: "other-ceiling" })
    ).toThrow(/source event does not match/);
    expect(() => insertRuntimeRunCommand(database!.db, { causationId: "unrelated-event" })).toThrow(
      /source event does not match/
    );
    expect(() => insertRuntimeRunCommand(database!.db, { actorRef: "other-actor" })).toThrow(
      /source event does not match/
    );
    expect(() => insertRuntimeRunCommand(database!.db, { authorityIssuedAtMs: 101 })).toThrow(
      /CHECK constraint failed/
    );
    expect(() =>
      insertRuntimeRunCommand(database!.db, {
        authorityIssuedAtMs: 90,
        authorityExpiresAtMs: 250,
      })
    ).not.toThrow();
    expect(() =>
      database!.db
        .prepare(`UPDATE runtime_run_commands SET command_json = '{"changed":true}'`)
        .run()
    ).toThrow(/Runtime Run commands are immutable/);
  });

  it("freezes source and applied Session events only after the Runtime journal references them", () => {
    database = openTeamSessionDatabase({ filename });
    seedRuntimeRunCommand(database.db);

    expect(() =>
      database!.db.prepare(`UPDATE session_events SET payload_json = '{}' WHERE sequence = 1`).run()
    ).toThrow(/Runtime Run journal events are immutable/);
    expect(() =>
      database!.db.prepare(`DELETE FROM session_events WHERE sequence = 1`).run()
    ).toThrow(/Runtime Run journal events are immutable/);

    insertRuntimeRequestEvent(database.db, 2, "event:not-yet-applied", { type: "run.paused" });
    expect(
      database.db
        .prepare(
          `UPDATE session_events SET actor_display_name = 'Alice Updated' WHERE sequence = 2`
        )
        .run().changes
    ).toBe(1);

    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'processing', attempts = 1, lease_owner = 'worker-1',
             lease_expires_at_ms = 200, updated_at_ms = 101
         WHERE command_id = 'runtime-command-1'`
      )
      .run();
    insertRuntimeRunReceipt(database.db);
    insertRuntimeRunEffect(database.db);

    expect(() =>
      database!.db.prepare(`UPDATE session_events SET payload_json = '{}' WHERE sequence = 2`).run()
    ).toThrow(/Runtime Run journal events are immutable/);
    expect(() =>
      database!.db.prepare(`DELETE FROM session_events WHERE sequence = 2`).run()
    ).toThrow(/Runtime Run journal events are immutable/);
  });

  it("allows only one unresolved Runtime Run command and never revives terminal dispatch", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");
    insertRuntimeRequestEvent(database.db, 1, "event:first-command");
    insertRuntimeRequestEvent(database.db, 2, "event:second-command", {
      commandId: "runtime-command-2",
    });
    insertRuntimeRunCommand(database.db);

    expect(() =>
      insertRuntimeRunCommand(database!.db, {
        commandId: "runtime-command-2",
        commandSequence: 2,
        previousCommandSequence: 1,
        sourceSessionSequence: 2,
        commandDigest: digestFor("runtime-command-2"),
      })
    ).toThrow(/UNIQUE constraint failed/);

    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'failed', last_safe_error_code = 'invalid_input',
             terminal_at_ms = 110, updated_at_ms = 110
         WHERE command_id = 'runtime-command-1'`
      )
      .run();
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'pending', terminal_at_ms = NULL, updated_at_ms = 111
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime Run command dispatch transition/);
  });

  it("requires every Runtime Run dispatch to begin as a clean pending row", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    insertRun(database.db, "run-1", "active");
    insertRuntimeRequestEvent(database.db, 1, "event:initial-dispatch");
    insertRuntimeRunCommand(database.db, { skipDispatch: true });

    expect(() =>
      database!.db
        .prepare(
          `INSERT INTO runtime_run_command_dispatch
             (command_id, agent_run_id, status, attempts, available_at_ms,
              created_at_ms, updated_at_ms, terminal_at_ms)
           VALUES ('runtime-command-1', 'run-1', 'failed', 0, 100, 100, 100, 100)`
        )
        .run()
    ).toThrow(/must begin pending/);
  });

  it("stores idempotent immutable receipts and rejects conflicting terminal receipts", () => {
    database = openTeamSessionDatabase({ filename });
    seedRuntimeRunCommand(database.db);

    expect(() => insertRuntimeRunReceipt(database!.db)).toThrow(
      /dispatch is not accepting receipts/
    );
    claimRuntimeRunDispatch(database.db, "runtime-command-1");
    expect(() => insertRuntimeRunReceipt(database!.db, { enforcedFence: 1 })).toThrow(
      /CHECK constraint failed/
    );
    insertRuntimeRunReceipt(database.db);
    expect(insertRuntimeRunReceipt(database.db, { ignoreExactDuplicate: true }).changes).toBe(0);
    expect(() =>
      insertRuntimeRunReceipt(database!.db, { receiptDigest: digestFor("conflict") })
    ).toThrow(/UNIQUE constraint failed/);
    expect(() =>
      insertRuntimeRunReceipt(database!.db, {
        receiptId: "receipt-2",
        version: 2,
        previousVersion: 1,
        outcome: "accepted",
        receiptDigest: digestFor("receipt-2"),
      })
    ).toThrow(/Invalid Runtime Run receipt version continuity|UNIQUE constraint failed/);
    expect(() =>
      insertRuntimeRunReceipt(database!.db, {
        receiptId: "receipt-incomplete-duplicate",
        version: 2,
        previousVersion: 1,
        outcome: "duplicate",
        originalOutcome: "enforced",
        originalReceiptDigest: digestFor("receipt-1"),
        receiptDigest: digestFor("incomplete-duplicate"),
        receiptJson: "{}",
      })
    ).toThrow(/CHECK constraint failed|JSON scope does not match/);
    expect(() =>
      database!.db
        .prepare(`UPDATE runtime_run_command_receipts SET receipt_json = '{"changed":true}'`)
        .run()
    ).toThrow(/Runtime Run command receipts are immutable/);
  });

  it("accepts a follow-ingested receipt while the exact dispatch awaits reconciliation", () => {
    database = openTeamSessionDatabase({ filename });
    seedRuntimeRunCommand(database.db);
    claimRuntimeRunDispatch(database.db, "runtime-command-1");
    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'awaiting-receipt', available_at_ms = 110,
             lease_owner = NULL, lease_expires_at_ms = NULL, updated_at_ms = 110
         WHERE command_id = 'runtime-command-1'`
      )
      .run();

    expect(() =>
      insertRuntimeRunReceipt(database!.db, {
        outcome: "accepted",
        receiptDigest: digestFor("follow-accepted"),
      })
    ).not.toThrow();
  });

  it("does not let duplicate receipts promote an accepted outcome", () => {
    database = openTeamSessionDatabase({ filename });
    seedRuntimeRunCommand(database.db);
    claimRuntimeRunDispatch(database.db, "runtime-command-1");
    const acceptedDigest = digestFor("receipt-accepted");
    insertRuntimeRunReceipt(database.db, {
      receiptId: "receipt-accepted",
      outcome: "accepted",
      receiptDigest: acceptedDigest,
    });
    insertRuntimeRunReceipt(database.db, {
      receiptId: "receipt-accepted-duplicate",
      version: 2,
      previousVersion: 1,
      outcome: "duplicate",
      originalOutcome: "accepted",
      originalReceiptDigest: acceptedDigest,
      receiptDigest: digestFor("receipt-accepted-duplicate"),
    });

    expect(() =>
      insertRuntimeRunReceipt(database!.db, {
        receiptId: "receipt-forged-promotion",
        version: 3,
        previousVersion: 2,
        outcome: "duplicate",
        originalOutcome: "enforced",
        originalReceiptDigest: digestFor("unseen-enforced-receipt"),
        receiptDigest: digestFor("receipt-forged-promotion"),
      })
    ).toThrow(/Invalid Runtime Run receipt version continuity/);
    expect(() =>
      insertRuntimeRunReceipt(database!.db, {
        receiptId: "receipt-changed-original",
        version: 3,
        previousVersion: 2,
        outcome: "duplicate",
        originalOutcome: "accepted",
        originalReceiptDigest: digestFor("different-accepted-receipt"),
        receiptDigest: digestFor("receipt-changed-original"),
      })
    ).toThrow(/Invalid Runtime Run receipt version continuity/);
    expect(() =>
      insertRuntimeRunReceipt(database!.db, {
        receiptId: "receipt-enforced",
        version: 3,
        previousVersion: 2,
        outcome: "enforced",
        receiptDigest: digestFor("receipt-enforced"),
      })
    ).not.toThrow();
  });

  it.each(["accepted", "enforced", "rejected", "quarantined"] as const)(
    "rejects a duplicate whose original %s receipt proof is incomplete",
    (originalOutcome) => {
      database = openTeamSessionDatabase({ filename });
      seedRuntimeRunCommand(database.db);
      claimRuntimeRunDispatch(database.db, "runtime-command-1");

      expect(() =>
        insertRuntimeRunReceipt(database!.db, {
          outcome: "duplicate",
          originalOutcome,
          incompleteOriginalProof: true,
        })
      ).toThrow(/CHECK constraint failed/);
    }
  );

  it.each(["rejected", "quarantined"] as const)(
    "terminalizes %s from a complete version-one duplicate receipt",
    (outcome) => {
      database = openTeamSessionDatabase({ filename });
      seedRuntimeRunCommand(database.db);
      database.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'processing', attempts = 1, lease_owner = 'worker-1',
               lease_expires_at_ms = 200, updated_at_ms = 101
           WHERE command_id = 'runtime-command-1'`
        )
        .run();
      insertRuntimeRunReceipt(database.db, {
        outcome: "duplicate",
        originalOutcome: outcome,
      });

      expect(() => terminalizeRuntimeRunDispatch(database!.db, 120, outcome)).not.toThrow();
    }
  );

  it("recovers an enforced effect from a complete version-one duplicate receipt", () => {
    database = openTeamSessionDatabase({ filename });
    seedRuntimeRunCommand(database.db);
    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'processing', attempts = 1, lease_owner = 'worker-1',
             lease_expires_at_ms = 200, updated_at_ms = 101
         WHERE command_id = 'runtime-command-1'`
      )
      .run();
    insertRuntimeRunReceipt(database.db, {
      outcome: "duplicate",
      originalOutcome: "enforced",
    });
    insertRuntimeRequestEvent(database.db, 2, "event:duplicate-pause-enforced", {
      type: "run.paused",
    });
    insertRuntimeRunEffect(database.db, digestFor("duplicate-effect"), {
      receiptOutcome: "duplicate",
    });
    database.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = 'paused', state_version = 2, updated_at_ms = 115
         WHERE id = 'run-1'`
      )
      .run();

    expect(() => terminalizeRuntimeRunDispatch(database!.db, 120)).not.toThrow();
  });

  it("terminalizes an enforced dispatch only after one immutable effect", () => {
    database = openTeamSessionDatabase({ filename });
    seedRuntimeRunCommand(database.db);
    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'processing', attempts = 1, lease_owner = 'worker-1',
             lease_expires_at_ms = 200, updated_at_ms = 101
         WHERE command_id = 'runtime-command-1'`
      )
      .run();
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET attempts = 2, lease_expires_at_ms = 220, updated_at_ms = 102
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime Run command dispatch transition/);
    insertRuntimeRunReceipt(database.db);

    expect(() => terminalizeRuntimeRunDispatch(database!.db, 120)).toThrow(
      /lacks durable evidence/
    );
    insertRuntimeRequestEvent(database.db, 2, "event:pause-enforced", { type: "run.paused" });
    for (const status of ["pending", "failed", "superseded"] as const) {
      const applyFromInvalidDispatch = database.db.transaction(() => {
        database!.db
          .prepare(
            `UPDATE runtime_run_command_dispatch
             SET status = ?, lease_owner = NULL, lease_expires_at_ms = NULL,
                 terminal_at_ms = ?, updated_at_ms = 112
             WHERE command_id = 'runtime-command-1'`
          )
          .run(status, status === "pending" ? null : 112);
        insertRuntimeRunEffect(database!.db);
      });
      expect(() => applyFromInvalidDispatch()).toThrow(
        /does not match current dispatch and Run state|Invalid Runtime Run command dispatch transition/
      );
    }
    for (const staleMutation of [
      `UPDATE agent_runs SET state_version = 2 WHERE id = 'run-1'`,
      `UPDATE agent_runs SET current_policy_revision = 2 WHERE id = 'run-1'`,
      `UPDATE agent_runs SET current_goal_set_revision = 2 WHERE id = 'run-1'`,
      `UPDATE agent_runs SET runtime_authorization_generation = 2 WHERE id = 'run-1'`,
      `UPDATE runtime_assignments SET status = 'recovering' WHERE id = '${ASSIGNMENT_ID}'`,
    ]) {
      const applyAgainstStaleRun = database.db.transaction(() => {
        database!.db.prepare(staleMutation).run();
        insertRuntimeRunEffect(database!.db);
      });
      expect(() => applyAgainstStaleRun()).toThrow(/does not match current dispatch and Run state/);
    }
    insertRuntimeRunEffect(database.db);
    expect(() => terminalizeRuntimeRunDispatch(database!.db, 120)).toThrow(
      /lacks durable evidence/
    );
    database.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = 'paused', state_version = 2, updated_at_ms = 115
         WHERE id = 'run-1'`
      )
      .run();
    expect(() => terminalizeRuntimeRunDispatch(database!.db, 120)).not.toThrow();
    expect(() => insertRuntimeRunEffect(database!.db, digestFor("second-effect"))).toThrow(
      /does not match current dispatch and Run state|UNIQUE constraint failed/
    );
    expect(() =>
      database!.db.prepare(`UPDATE runtime_run_command_effects SET applied_at_ms = 121`).run()
    ).toThrow(/Runtime Run command effects are immutable/);
  });
});

function seedRuntimeRunCommand(db: Database.Database): void {
  seedSessionAndAssignment(db);
  insertRun(db, "run-1", "active");
  insertRuntimeRequestEvent(db, 1, "event:pause-requested");
  insertRuntimeRunCommand(db);
}

function seedStartingRuntimeRunCommand(db: Database.Database): void {
  seedSessionAndAssignment(db);
  db.transaction(() => {
    db.prepare(
      `INSERT INTO agent_runs
         (id, session_id, team_id, project_id, runtime_assignment_id, start_command_id,
          lifecycle, current_policy_revision, current_goal_set_revision,
          runtime_authorization_generation, created_by_user_id, created_at_ms, updated_at_ms)
       VALUES ('run-1', ?, ?, ?, ?, 'runtime-command-start',
               'starting', 1, 1, 1, 'user-alice', 10, 10)`
    ).run(SESSION_ID, TEAM_ID, PROJECT_ID, ASSIGNMENT_ID);
    db.prepare(
      `INSERT INTO goal_sets
         (goal_set_id, agent_run_id, revision, previous_revision, digest, created_at_ms)
       VALUES ('goal-set-1', 'run-1', 1, NULL, ?, 20)`
    ).run(digestFor("goal-set:run-1:1"));
    db.prepare(
      `INSERT INTO run_policy_revisions
         (agent_run_id, session_id, revision, previous_revision, digest, policy_body_digest,
          mode, completion_policy,
          scoped_external_policy_ref, scoped_external_rules_json, limits_json,
          initial_goal_set_id, initial_goal_set_revision,
          project_ceiling_revision, project_ceiling_digest,
          runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id,
          runtime_authorization_generation, yolo_confirmation_ref, created_at_ms)
       VALUES
         ('run-1', ?, 1, NULL, ?, ?, 'autonomous', 'continue-until-all-goals-achieved',
          'scoped-policy-1', '[]', ?, 'goal-set-1', 1,
          'ceiling-1', ?, ?, 1, 'sandbox-1', 1, 'principal-1', 1, NULL, 20)`
    ).run(
      SESSION_ID,
      digestFor("policy-snapshot:run-1:1"),
      digestFor("policy-body:run-1:1"),
      JSON.stringify(completeLimits()),
      digestFor("project-ceiling"),
      ASSIGNMENT_ID
    );
    insertRuntimeRequestEvent(db, 1, "event:start-requested", {
      commandId: "runtime-command-start",
      operation: "run.start",
    });
    insertRuntimeRunCommand(db, {
      commandId: "runtime-command-start",
      operation: "run.start",
      targetLifecycle: "active",
    });
  })();
}

function claimRuntimeRunDispatch(
  db: Database.Database,
  commandId: string,
  now = 101,
  worker = "worker-1"
): void {
  db.prepare(
    `UPDATE runtime_run_command_dispatch
     SET status = 'processing', attempts = attempts + 1, lease_owner = ?,
         lease_expires_at_ms = 200, updated_at_ms = ?
     WHERE command_id = ?`
  ).run(worker, now, commandId);
}

function insertRuntimeRequestEvent(
  db: Database.Database,
  sequence: number,
  eventId: string,
  options: {
    commandId?: string;
    type?: string;
    operation?: "run.start" | "run.pause" | "run.resume" | "run.stop";
    fromRunStateVersion?: number;
    toRunStateVersion?: number;
    targetLifecycle?: "active" | "paused" | "stopped";
  } = {}
): void {
  const commandId = options.commandId ?? "runtime-command-1";
  const eventType = options.type ?? "run.runtime-command.requested";
  const operation = options.operation ?? "run.pause";
  const fromRunStateVersion = options.fromRunStateVersion ?? 1;
  const toRunStateVersion = options.toRunStateVersion ?? 2;
  const targetLifecycle =
    options.targetLifecycle ??
    (operation === "run.pause" ? "paused" : operation === "run.stop" ? "stopped" : "active");
  db.prepare(
    `INSERT INTO session_events
       (session_id, sequence, event_id, type, occurred_at_ms,
        actor_kind, actor_user_id, actor_display_name,
        source_scope, source_key, payload_json)
     VALUES (?, ?, ?, ?, 100,
             'human', 'user-alice', 'Alice', 'vitest:runtime-command', ?, ?)`
  ).run(
    SESSION_ID,
    sequence,
    eventId,
    eventType,
    eventId,
    JSON.stringify({
      commandId,
      agentRunId: "run-1",
      operation,
      fromRunStateVersion,
      toRunStateVersion,
      targetLifecycle,
    })
  );
}

function insertRuntimeRunCommand(
  db: Database.Database,
  options: {
    commandId?: string;
    commandSequence?: number;
    previousCommandSequence?: number | null;
    operation?: "run.start" | "run.pause" | "run.resume" | "run.stop";
    targetLifecycle?: "active" | "paused" | "stopped";
    targetRunStateVersion?: number;
    sandboxGeneration?: number;
    sourceSessionSequence?: number;
    commandDigest?: string;
    commandJson?: string;
    skipDispatch?: boolean;
    omitPerKindField?: boolean;
    projectCeilingRevision?: string;
    causationId?: string;
    actorRef?: string;
    authorityIssuedAtMs?: number;
    authorityExpiresAtMs?: number;
  } = {}
): void {
  const commandId = options.commandId ?? "runtime-command-1";
  const commandSequence = options.commandSequence ?? 1;
  const previousCommandSequence =
    options.previousCommandSequence === undefined ? null : options.previousCommandSequence;
  const operation = options.operation ?? "run.pause";
  const targetLifecycle = options.targetLifecycle ?? "paused";
  const targetRunStateVersion = options.targetRunStateVersion ?? 2;
  const sandboxGeneration = options.sandboxGeneration ?? 1;
  const sourceSessionSequence = options.sourceSessionSequence ?? 1;
  const commandDigest = options.commandDigest ?? digestFor(commandId);
  const sourceEvent = db
    .prepare(
      `SELECT event_id, actor_kind, actor_user_id FROM session_events
       WHERE session_id = ? AND sequence = ?`
    )
    .get(SESSION_ID, sourceSessionSequence) as
    | { event_id: string; actor_kind: "human" | "system"; actor_user_id: string }
    | undefined;
  if (!sourceEvent) throw new Error("Expected a Runtime command source event");
  const policy = db
    .prepare(
      `SELECT digest, policy_body_digest, project_ceiling_revision
       FROM run_policy_revisions
       WHERE agent_run_id = 'run-1' AND revision = 1`
    )
    .get() as
    | { digest: string; policy_body_digest: string; project_ceiling_revision: string }
    | undefined;
  if (!policy) throw new Error("Expected a Runtime command policy");
  const goalSet = db
    .prepare(
      `SELECT goal_set_id, digest FROM goal_sets
       WHERE agent_run_id = 'run-1' AND revision = 1`
    )
    .get() as { goal_set_id: string; digest: string } | undefined;
  if (!goalSet) throw new Error("Expected a Runtime command Goal Set");
  const authorityDigest = digestFor(`authority:${commandId}`);
  const commandJson =
    options.commandJson ??
    JSON.stringify({
      commandId,
      kind: operation,
      agentRunId: "run-1",
      runPolicyRevision: 1,
      fromRunStateVersion: 1,
      toRunStateVersion: targetRunStateVersion,
      projectCeilingRevision: options.projectCeilingRevision ?? policy.project_ceiling_revision,
      causationId: options.causationId ?? sourceEvent.event_id,
      actor: {
        kind: sourceEvent.actor_kind,
        actorRef: options.actorRef ?? sourceEvent.actor_user_id,
      },
      issuedAtMs: 100,
      deadlineAtMs: 200,
      authority: {
        issuer: "team-session",
        issuerKeyId: "team-session:test-key",
        audience: "runtime",
        capability: operation,
        claimsDigest: authorityDigest,
        issuedAtMs: options.authorityIssuedAtMs ?? 100,
        expiresAtMs: options.authorityExpiresAtMs ?? 200,
        signature: "test-signature",
      },
      runtimeAuthorizationGeneration: 1,
      binding: {
        teamId: TEAM_ID,
        projectId: PROJECT_ID,
        sessionId: SESSION_ID,
        runtimeAssignmentId: ASSIGNMENT_ID,
        runtimeAssignmentGeneration: 1,
        sandboxId: "sandbox-1",
        sandboxGeneration,
        runtimePrincipalId: "principal-1",
      },
      ...(operation === "run.start"
        ? {
            policy: {
              agentRunId: "run-1",
              revision: 1,
              digest: policy.digest,
              policyBodyDigest: policy.policy_body_digest,
              projectCeilingRevision: policy.project_ceiling_revision,
              initialGoalSet: {
                agentRunId: "run-1",
                goalSetId: goalSet.goal_set_id,
                revision: 1,
                digest: goalSet.digest,
              },
              runtimeAuthorizationGeneration: 1,
              binding: {
                runtimeAssignmentId: ASSIGNMENT_ID,
                runtimeAssignmentGeneration: 1,
                sandboxId: "sandbox-1",
                sandboxGeneration,
                runtimePrincipalId: "principal-1",
              },
            },
          }
        : {}),
      ...(operation === "run.pause" && !options.omitPerKindField ? { reason: "human" } : {}),
      ...(operation === "run.resume" && !options.omitPerKindField
        ? { accountableAssigneePresent: true }
        : {}),
      ...(operation === "run.stop" && !options.omitPerKindField ? { reason: "human" } : {}),
    });
  db.transaction(() => {
    db.prepare(
      `INSERT INTO runtime_run_commands
         (id, session_id, agent_run_id, command_sequence, previous_command_sequence,
          operation, target_lifecycle, expected_run_state_version, target_run_state_version,
          run_policy_revision, goal_set_id, goal_set_revision,
          runtime_assignment_id, runtime_assignment_generation, sandbox_id,
          sandbox_generation, runtime_principal_id, runtime_authorization_generation,
          source_session_sequence, command_json, command_digest, authority_digest,
          created_at_ms, deadline_at_ms)
       VALUES (?, ?, 'run-1', ?, ?, ?, ?, 1, ?, 1, 'goal-set-1', 1,
               ?, 1, 'sandbox-1', ?, 'principal-1', 1,
               ?, ?, ?, ?, 100, 200)`
    ).run(
      commandId,
      SESSION_ID,
      commandSequence,
      previousCommandSequence,
      operation,
      targetLifecycle,
      targetRunStateVersion,
      ASSIGNMENT_ID,
      sandboxGeneration,
      sourceSessionSequence,
      commandJson,
      commandDigest,
      authorityDigest
    );
    if (!options.skipDispatch) {
      db.prepare(
        `INSERT INTO runtime_run_command_dispatch
           (command_id, agent_run_id, status, attempts, available_at_ms,
            created_at_ms, updated_at_ms)
         VALUES (?, 'run-1', 'pending', 0, 100, 100, 100)`
      ).run(commandId);
    }
  })();
}

function insertRuntimeRunReceipt(
  db: Database.Database,
  options: {
    commandId?: string;
    receiptId?: string;
    version?: number;
    previousVersion?: number | null;
    outcome?: "accepted" | "enforced" | "duplicate" | "rejected" | "quarantined";
    receiptDigest?: string;
    originalOutcome?: "accepted" | "enforced" | "rejected" | "quarantined";
    originalReceiptDigest?: string;
    enforcedFence?: number;
    receiptJson?: string;
    incompleteOriginalProof?: boolean;
    ignoreExactDuplicate?: boolean;
  } = {}
) {
  const commandId = options.commandId ?? "runtime-command-1";
  const receiptId = options.receiptId ?? "receipt-1";
  const version = options.version ?? 1;
  const previousVersion = options.previousVersion === undefined ? null : options.previousVersion;
  const outcome = options.outcome ?? "enforced";
  const receiptDigest = options.receiptDigest ?? digestFor("receipt-1");
  const duplicate = outcome === "duplicate";
  const originalOutcome = duplicate ? (options.originalOutcome ?? "enforced") : null;
  const originalReceiptDigest = duplicate
    ? (options.originalReceiptDigest ?? digestFor("original-receipt"))
    : null;
  const binding = {
    teamId: TEAM_ID,
    projectId: PROJECT_ID,
    sessionId: SESSION_ID,
    runtimeAssignmentId: ASSIGNMENT_ID,
    runtimeAssignmentGeneration: 1,
    sandboxId: "sandbox-1",
    sandboxGeneration: 1,
    runtimePrincipalId: "principal-1",
  };
  const receiptBase = {
    commandId,
    outcome,
    binding,
    runtimeAuthorizationGeneration: 1,
  };
  const originalOutcomeProof =
    originalOutcome === "accepted"
      ? options.incompleteOriginalProof
        ? {}
        : { effectRef: "effect:original" }
      : originalOutcome === "enforced"
        ? options.incompleteOriginalProof
          ? { enforcedFence: 2 }
          : { enforcedFence: 2, effectRef: "effect:original" }
        : originalOutcome === "rejected"
          ? options.incompleteOriginalProof
            ? { code: "stale_fence" }
            : { code: "stale_fence", safeDetail: "The fence is stale" }
          : originalOutcome === "quarantined"
            ? options.incompleteOriginalProof
              ? { reason: "isolation_failure" }
              : { reason: "isolation_failure", effectRef: "effect:original" }
            : {};
  const receiptJson =
    options.receiptJson ??
    JSON.stringify(
      duplicate
        ? {
            ...receiptBase,
            originalReceiptDigest,
            originalReceipt: {
              commandId,
              outcome: originalOutcome,
              binding,
              runtimeAuthorizationGeneration: 1,
              ...originalOutcomeProof,
            },
          }
        : outcome === "enforced"
          ? {
              ...receiptBase,
              enforcedFence: options.enforcedFence ?? 2,
              effectRef: "effect:runtime-command-1",
            }
          : outcome === "accepted"
            ? { ...receiptBase, effectRef: "effect:runtime-command-1" }
            : outcome === "rejected"
              ? { ...receiptBase, code: "stale_fence", safeDetail: "The fence is stale" }
              : outcome === "quarantined"
                ? {
                    ...receiptBase,
                    reason: "isolation_failure",
                    effectRef: "effect:runtime-command-1",
                  }
                : receiptBase
    );
  return db
    .prepare(
      `INSERT ${options.ignoreExactDuplicate ? "OR IGNORE " : ""}INTO runtime_run_command_receipts
         (id, command_id, version, previous_version, session_id, agent_run_id,
          command_sequence, run_policy_revision, goal_set_id, goal_set_revision,
          runtime_assignment_id, runtime_assignment_generation, sandbox_id,
          sandbox_generation, runtime_principal_id, runtime_authorization_generation,
          expected_run_state_version, target_run_state_version, source_session_sequence,
          command_digest, outcome, original_outcome, original_receipt_digest,
          receipt_json, receipt_digest, received_at_ms)
       VALUES (?, ?, ?, ?, ?, 'run-1', 1, 1, 'goal-set-1', 1,
               ?, 1, 'sandbox-1', 1, 'principal-1', 1, 1, 2, 1,
               ?, ?, ?, ?, ?, ?, 110)`
    )
    .run(
      receiptId,
      commandId,
      version,
      previousVersion,
      SESSION_ID,
      ASSIGNMENT_ID,
      digestFor(commandId),
      outcome,
      originalOutcome,
      originalReceiptDigest,
      receiptJson,
      receiptDigest
    );
}

function insertRuntimeRunEffect(
  db: Database.Database,
  effectDigest = digestFor("effect-1"),
  options: {
    commandId?: string;
    receiptId?: string;
    receiptOutcome?: "enforced" | "duplicate";
  } = {}
): void {
  const commandId = options.commandId ?? "runtime-command-1";
  db.prepare(
    `INSERT INTO runtime_run_command_effects
       (command_id, receipt_id, receipt_outcome, session_id, agent_run_id,
        command_sequence, expected_run_state_version, target_run_state_version,
        source_session_sequence, applied_session_sequence, effect_digest, applied_at_ms)
     VALUES (?, ?, ?, ?, 'run-1',
             1, 1, 2, 1, 2, ?, 115)`
  ).run(
    commandId,
    options.receiptId ?? "receipt-1",
    options.receiptOutcome ?? "enforced",
    SESSION_ID,
    effectDigest
  );
}

function terminalizeRuntimeRunDispatch(
  db: Database.Database,
  now: number,
  status: "enforced" | "rejected" | "quarantined" = "enforced",
  commandId = "runtime-command-1"
): void {
  db.prepare(
    `UPDATE runtime_run_command_dispatch
     SET status = ?, lease_owner = NULL, lease_expires_at_ms = NULL,
         terminal_at_ms = ?, updated_at_ms = ?
     WHERE command_id = ?`
  ).run(status, now, now, commandId);
}

function seedSessionAndAssignment(db: Database.Database): void {
  db.prepare(`INSERT INTO teams (id, name, created_at_ms) VALUES (?, 'Acme', 1)`).run(TEAM_ID);
  db.prepare(
    `INSERT INTO projects (id, team_id, name, created_at_ms) VALUES (?, ?, 'Terminal X', 1)`
  ).run(PROJECT_ID, TEAM_ID);
  db.prepare(
    `INSERT INTO sessions
       (id, team_id, project_id, name, status, steering_policy,
        runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
     VALUES (?, ?, ?, 'Session', 'active', 'shared',
       'local-tmux', 'trusted-shared-host', 'phase-four-schema', 0, 1)`
  ).run(SESSION_ID, TEAM_ID, PROJECT_ID);
  db.prepare(
    `INSERT INTO runtime_assignments
       (id, session_id, team_id, project_id, generation, runtime_kind,
        sandbox_id, sandbox_generation, runtime_principal_id,
        runtime_authorization_generation, status, created_at_ms)
     VALUES (?, ?, ?, ?, 1, 'local-tmux', 'sandbox-1', 1, 'principal-1', 1, 'ready', 2)`
  ).run(ASSIGNMENT_ID, SESSION_ID, TEAM_ID, PROJECT_ID);
  db.prepare(
    `INSERT INTO runtime_authorization_epochs
       (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
        sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms)
     VALUES (?, 1, ?, 1, 'sandbox-1', 1, 'principal-1', 2)`
  ).run(SESSION_ID, ASSIGNMENT_ID);
}

function seedOtherSessionAndAssignment(db: Database.Database): void {
  db.prepare(
    `INSERT INTO sessions
       (id, team_id, project_id, name, status, steering_policy,
        runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
     VALUES (?, ?, ?, 'Other Session', 'active', 'shared',
       'local-tmux', 'trusted-shared-host', 'phase-four-schema-other', 0, 1)`
  ).run(OTHER_SESSION_ID, TEAM_ID, PROJECT_ID);
  db.prepare(
    `INSERT INTO runtime_assignments
       (id, session_id, team_id, project_id, generation, runtime_kind,
        sandbox_id, sandbox_generation, runtime_principal_id,
        runtime_authorization_generation, status, created_at_ms)
     VALUES (?, ?, ?, ?, 1, 'local-tmux', 'sandbox-2', 1, 'principal-2', 1, 'ready', 2)`
  ).run(OTHER_ASSIGNMENT_ID, OTHER_SESSION_ID, TEAM_ID, PROJECT_ID);
  db.prepare(
    `INSERT INTO runtime_authorization_epochs
       (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
        sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms)
     VALUES (?, 1, ?, 1, 'sandbox-2', 1, 'principal-2', 2)`
  ).run(OTHER_SESSION_ID, OTHER_ASSIGNMENT_ID);
}

function insertRun(
  db: Database.Database,
  runId: string,
  lifecycle: "active" | "paused" | "completed"
): void {
  const goalSetId = runId === "run-1" ? "goal-set-1" : `goal-set:${runId}`;
  db.transaction(() => {
    insertDanglingRun(db, runId, lifecycle);
    db.prepare(
      `INSERT INTO goal_sets
         (goal_set_id, agent_run_id, revision, previous_revision, digest, created_at_ms)
       VALUES (?, ?, 1, NULL, ?, 20)`
    ).run(goalSetId, runId, digestFor(`goal-set:${runId}:1`));
    db.prepare(
      `INSERT INTO run_policy_revisions
         (agent_run_id, session_id, revision, previous_revision, digest, policy_body_digest,
          mode, completion_policy,
          scoped_external_policy_ref, scoped_external_rules_json, limits_json,
          initial_goal_set_id, initial_goal_set_revision,
          project_ceiling_revision, project_ceiling_digest,
          runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id,
          runtime_authorization_generation, yolo_confirmation_ref, created_at_ms)
       VALUES
         (?, ?, 1, NULL, ?, ?, 'autonomous', 'continue-until-all-goals-achieved',
          'scoped-policy-1', '[]', ?, ?, 1,
          'ceiling-1', ?, ?, 1, 'sandbox-1', 1, 'principal-1', 1, NULL, 20)`
    ).run(
      runId,
      SESSION_ID,
      digestFor(`policy-snapshot:${runId}:1`),
      digestFor(`policy-body:${runId}:1`),
      JSON.stringify(completeLimits()),
      goalSetId,
      digestFor("project-ceiling"),
      ASSIGNMENT_ID
    );
  })();
}

function insertDanglingRun(
  db: Database.Database,
  runId: string,
  lifecycle: "active" | "paused" | "completed"
): void {
  const terminalAtMs = lifecycle === "completed" ? 11 : null;
  db.prepare(
    `INSERT INTO agent_runs
       (id, session_id, team_id, project_id, runtime_assignment_id, lifecycle,
        current_policy_revision, current_goal_set_revision, runtime_authorization_generation,
        created_by_user_id, created_at_ms, updated_at_ms, terminal_at_ms)
     VALUES (?, ?, ?, ?, ?, ?, 1, 1, 1, 'user-alice', 10, ?, ?)`
  ).run(
    runId,
    SESSION_ID,
    TEAM_ID,
    PROJECT_ID,
    ASSIGNMENT_ID,
    lifecycle,
    terminalAtMs ?? 10,
    terminalAtMs
  );
}

function insertTerminalRun(db: Database.Database, runId: string): void {
  insertRun(db, runId, "completed");
}

function completeLimits(): Record<string, unknown> {
  return {
    wallClock: { kind: "unconfigured" },
    modelTokens: { kind: "unconfigured" },
    modelSpend: { kind: "unconfigured" },
    outboundBytes: { kind: "unconfigured" },
    actionCounts: {
      local: { kind: "unconfigured" },
      "scoped-external": { kind: "unconfigured" },
      protected: { kind: "unconfigured" },
      forbidden: { kind: "unconfigured" },
    },
  };
}

function insertPolicy(
  db: Database.Database,
  limits: Record<string, unknown>,
  options: {
    assignmentId?: string;
    sandboxId?: string;
    runtimePrincipalId?: string;
    goalSetId?: string;
  } = {}
): void {
  const assignmentId = options.assignmentId ?? ASSIGNMENT_ID;
  const sandboxId = options.sandboxId ?? "sandbox-1";
  const runtimePrincipalId = options.runtimePrincipalId ?? "principal-1";
  const goalSetId = options.goalSetId ?? "goal-set-1";
  db.prepare(
    `INSERT INTO run_policy_revisions
       (agent_run_id, session_id, revision, previous_revision, digest, policy_body_digest,
        mode, completion_policy,
        scoped_external_policy_ref, scoped_external_rules_json, limits_json,
        initial_goal_set_id, initial_goal_set_revision,
        project_ceiling_revision, project_ceiling_digest,
        runtime_assignment_id, runtime_assignment_generation,
        sandbox_id, sandbox_generation, runtime_principal_id,
        runtime_authorization_generation, yolo_confirmation_ref, created_at_ms)
     VALUES
       ('run-1', ?, 2, 1, ?, ?, 'autonomous', 'continue-until-all-goals-achieved',
        'scoped-policy-1', '[]', ?, ?, 1,
        'ceiling-1', ?, ?, 1, ?, 1, ?, 1, NULL, 20)`
  ).run(
    SESSION_ID,
    digestFor("policy-snapshot:run-1:2"),
    digestFor("policy-body:run-1:2"),
    JSON.stringify(limits),
    goalSetId,
    digestFor("project-ceiling"),
    assignmentId,
    sandboxId,
    runtimePrincipalId
  );
}

function insertGoal(db: Database.Database, position: number, title: string): void {
  db.prepare(
    `INSERT INTO goals
       (agent_run_id, goal_set_id, goal_set_revision, goal_id, position, version, title,
        acceptance_criteria_json, dependency_goal_ids_json, status)
     VALUES ('run-1', 'goal-set-1', 1, 'goal-1', ?, 1, ?, '["passes"]', '[]', 'pending')`
  ).run(position, title);
}

function insertEvidence(
  db: Database.Database,
  evidenceId: string,
  status: "proposed" | "validated",
  reviewedAtMs?: number
): void {
  db.prepare(
    `INSERT INTO goal_evidence
       (id, agent_run_id, goal_set_id, goal_set_revision, goal_id, goal_version,
        evidence_ref, evidence_digest, status, created_at_ms, reviewed_at_ms)
     VALUES (?, 'run-1', 'goal-set-1', 1, 'goal-1', 1, ?, ?, ?, 30, ?)`
  ).run(evidenceId, `artifact:${evidenceId}`, digestFor(evidenceId), status, reviewedAtMs ?? null);
}

function insertEvidenceBinding(
  db: Database.Database,
  input: { evidenceId: string; agentRunId: string; goalVersion: number }
): void {
  db.prepare(
    `INSERT INTO goal_evidence
       (id, agent_run_id, goal_set_id, goal_set_revision, goal_id, goal_version,
        evidence_ref, evidence_digest, status, created_at_ms, reviewed_at_ms)
     VALUES (?, ?, 'goal-set-1', 1, 'goal-1', ?, ?, ?, 'proposed', 30, NULL)`
  ).run(
    input.evidenceId,
    input.agentRunId,
    input.goalVersion,
    `artifact:${input.evidenceId}`,
    digestFor(input.evidenceId)
  );
}

function insertManifest(
  db: Database.Database,
  options: {
    manifestId?: string;
    agentRunId?: string;
    digest?: string;
    effectIdempotencyKey?: string;
  } = {}
): void {
  const manifestId = options.manifestId ?? "manifest-1";
  const agentRunId = options.agentRunId ?? "run-1";
  const digest = options.digest ?? digestFor("manifest");
  const effectIdempotencyKey = options.effectIdempotencyKey ?? "effect-1";
  db.prepare(
    `INSERT INTO action_manifests
       (id, version, session_id, agent_run_id, digest, action_class, provider, operation,
        exact_target, action_schema_id, action_schema_version, action_schema_digest,
        canonical_effect_input_digest, effect_idempotency_key, expected_effect_json,
        expires_at_ms, created_at_ms)
     VALUES
       (?, 1, ?, ?, ?, 'scoped-external', 'github', 'branch.push',
        'repo:branch', 'github.branch.push', 1, ?, ?, ?, '{}', 100, 30)`
  ).run(
    manifestId,
    SESSION_ID,
    agentRunId,
    digest,
    digestFor("schema"),
    digestFor("effect"),
    effectIdempotencyKey
  );
}

function insertApproval(
  db: Database.Database,
  actionClass: "local" | "scoped-external" | "forbidden",
  options: {
    approvalId?: string;
    status?: "approved" | "denied";
    subjectKind?: "manifest" | "run-pattern";
    manifestId?: string;
    manifestDigest?: string;
  } = {}
): void {
  const approvalId = options.approvalId ?? "approval-1";
  const status = options.status ?? "approved";
  const subjectKind = options.subjectKind ?? "manifest";
  const manifestId = subjectKind === "manifest" ? (options.manifestId ?? "manifest-1") : null;
  const manifestDigest =
    subjectKind === "manifest" ? (options.manifestDigest ?? digestFor("manifest")) : null;
  const actionPatternDigest = subjectKind === "run-pattern" ? digestFor("run-pattern") : null;
  const actionPatternJson =
    subjectKind === "run-pattern"
      ? JSON.stringify({
          actionClass: "scoped-external",
          provider: "github",
          operation: "branch.push",
          targetPattern: "repo:branch",
          eligibleUse: "session_branch_push",
          digest: actionPatternDigest,
        })
      : null;
  const subjectDigest = manifestDigest ?? actionPatternDigest;
  const insert = db.prepare(
    `INSERT INTO approval_requests
       (id, version, previous_version, request_digest, session_id, agent_run_id,
        run_policy_revision, runtime_assignment_id, runtime_assignment_generation,
        sandbox_id, sandbox_generation, runtime_principal_id,
        runtime_authorization_generation, action_class, provider, operation, exact_target,
        subject_kind, manifest_id, manifest_digest, action_pattern_json,
        action_pattern_digest, subject_digest, status, expires_at_ms, created_at_ms,
        resolved_at_ms, resolved_by_actor_ref)
     VALUES
       (?, ?, ?, ?, ?, 'run-1', 1, ?, 1,
        'sandbox-1', 1, 'principal-1', 1, ?, 'github', 'branch.push', 'repo:branch',
        ?, ?, ?, ?, ?, ?, ?, 100, 40, ?, ?)`
  );
  const common = [
    approvalId,
    SESSION_ID,
    ASSIGNMENT_ID,
    actionClass,
    subjectKind,
    manifestId,
    manifestDigest,
    actionPatternJson,
    actionPatternDigest,
    subjectDigest,
  ] as const;
  insert.run(
    common[0],
    1,
    null,
    digestFor(`open:${approvalId}:${actionClass}`),
    ...common.slice(1),
    "open",
    null,
    null
  );
  insert.run(
    common[0],
    2,
    1,
    digestFor(`${status}:${approvalId}:${actionClass}`),
    ...common.slice(1),
    status,
    40,
    "user-alice"
  );
}

function insertGrant(
  db: Database.Database,
  actionClass: "local" | "scoped-external" | "protected",
  scope: "once" | "run",
  options: { approvalId?: string; grantId?: string } = {}
): void {
  const approvalId = options.approvalId ?? "approval-1";
  const grantId = options.grantId ?? "grant-1";
  const approvalSubjectKind = scope === "once" ? "manifest" : "run-pattern";
  const manifestDigest = scope === "once" ? digestFor("manifest") : null;
  const actionPatternDigest = scope === "run" ? digestFor("run-pattern") : null;
  const actionPatternJson =
    scope === "run"
      ? JSON.stringify({
          actionClass: "scoped-external",
          provider: "github",
          operation: "branch.push",
          targetPattern: "repo:branch",
          eligibleUse: "session_branch_push",
          digest: actionPatternDigest,
        })
      : null;
  const scopeDigest = manifestDigest ?? actionPatternDigest;
  db.prepare(
    `INSERT INTO action_grants
       (id, session_id, agent_run_id, run_policy_revision,
        runtime_assignment_id, runtime_assignment_generation, sandbox_id, sandbox_generation,
        runtime_principal_id, runtime_authorization_generation,
        approval_request_id, approval_request_version, approval_status, approval_subject_kind,
        action_class, provider, operation,
        target, budget_json, usage_ledger_ref, scope_kind,
        scope_digest, manifest_digest, effect_idempotency_key, action_pattern_json,
        action_pattern_digest, eligible_run_use,
        issuer_actor_ref, issuer_approval_authority_revision,
        expires_at_ms, signature, created_at_ms)
     VALUES
       (?, ?, 'run-1', 1, ?, 1, 'sandbox-1', 1,
        'principal-1', 1, ?, 2, 'approved', ?, ?, 'github', 'branch.push',
        'repo:branch', '{}', 'ledger-1', ?, ?, ?, ?, ?, ?, ?,
        'user-alice', 'authority-1', 90, 'signature', 50)`
  ).run(
    grantId,
    SESSION_ID,
    ASSIGNMENT_ID,
    approvalId,
    approvalSubjectKind,
    actionClass,
    scope,
    scopeDigest,
    manifestDigest,
    scope === "once" ? "effect-1" : null,
    actionPatternJson,
    actionPatternDigest,
    scope === "run" ? "session_branch_push" : null
  );
  db.prepare(
    `INSERT INTO action_grant_states
       (grant_id, version, previous_version, status, reason, actor_ref, created_at_ms)
     VALUES (?, 1, NULL, 'issued', 'issued', 'user-alice', 50)`
  ).run(grantId);
}

function insertGrantReview(db: Database.Database, safeDefault: string): void {
  db.prepare(
    `INSERT INTO grant_reviews
       (id, version, previous_version, session_id, agent_run_id, reason, safe_default,
        status, stale_grant_ids_json, intentionally_revoked_grant_ids_json,
        reissuable_candidate_grant_ids_json, target_run_policy_revision,
        target_runtime_assignment_id, target_runtime_assignment_generation,
        target_sandbox_id, target_sandbox_generation, target_runtime_principal_id,
        target_runtime_authorization_generation, created_at_ms)
     VALUES
       ('grant-review-1', 1, NULL, ?, 'run-1', 'runtime-authorization', ?,
        'open', '[]', '[]', '[]', 1, ?, 1, 'sandbox-1', 1, 'principal-1', 1, 60)`
  ).run(SESSION_ID, safeDefault, ASSIGNMENT_ID);
}

function digestFor(value: string): string {
  return Buffer.from(value).toString("hex").padEnd(64, "0").slice(0, 64);
}

function createAgentRunSchemaV2Fixture(filename: string): void {
  const db = new Database(filename);
  try {
    db.exec(`
      CREATE TABLE teams (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
      ) STRICT;

      CREATE TABLE projects (
        id TEXT PRIMARY KEY,
        team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
        name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
        source_ref TEXT,
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
        UNIQUE (id, team_id)
      ) STRICT;

      CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        team_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
        status TEXT NOT NULL CHECK (status IN ('active', 'awaiting_assignee', 'ended')),
        steering_policy TEXT NOT NULL CHECK (steering_policy IN ('single', 'shared')),
        access_revision INTEGER NOT NULL DEFAULT 1 CHECK (access_revision >= 1),
        assignee_revision INTEGER NOT NULL DEFAULT 1 CHECK (assignee_revision >= 1),
        supervision_revision INTEGER NOT NULL DEFAULT 1 CHECK (supervision_revision >= 1),
        steering_revision INTEGER NOT NULL DEFAULT 1 CHECK (steering_revision >= 1),
        control_revision INTEGER NOT NULL DEFAULT 1 CHECK (control_revision >= 1),
        control_epoch INTEGER NOT NULL DEFAULT 1 CHECK (control_epoch >= 1),
        runtime_authorization_generation INTEGER NOT NULL DEFAULT 1
          CHECK (runtime_authorization_generation >= 1),
        runtime_authorization_state TEXT NOT NULL DEFAULT 'enforced'
          CHECK (runtime_authorization_state IN ('enforced', 'pending', 'quarantined')),
        next_sequence INTEGER NOT NULL DEFAULT 1 CHECK (next_sequence >= 1),
        runtime_kind TEXT NOT NULL CHECK (runtime_kind = 'local-tmux'),
        isolation TEXT NOT NULL CHECK (isolation = 'trusted-shared-host'),
        tmux_name TEXT NOT NULL CHECK (length(tmux_name) BETWEEN 1 AND 128),
        yolo_eligible INTEGER NOT NULL DEFAULT 0 CHECK (yolo_eligible = 0),
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
        UNIQUE (team_id, name),
        UNIQUE (tmux_name),
        UNIQUE (id, team_id, project_id),
        FOREIGN KEY (project_id, team_id) REFERENCES projects(id, team_id) ON DELETE RESTRICT
      ) STRICT;

      CREATE TABLE session_events (
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
        sequence INTEGER NOT NULL CHECK (sequence >= 1),
        event_id TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL,
        occurred_at_ms INTEGER NOT NULL CHECK (occurred_at_ms >= 0),
        actor_kind TEXT NOT NULL CHECK (actor_kind IN ('human', 'system')),
        actor_user_id TEXT NOT NULL,
        actor_display_name TEXT NOT NULL,
        source_scope TEXT NOT NULL,
        source_key TEXT NOT NULL,
        payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
        PRIMARY KEY (session_id, sequence)
      ) STRICT;

      PRAGMA application_id = 1415074609;
      PRAGMA user_version = 2;
    `);
  } finally {
    db.close();
  }
}

function createRuntimeRunSchemaV3Fixture(filename: string): {
  outbox: Record<string, unknown>;
  sourceEvent: Record<string, unknown>;
  session: Record<string, unknown>;
} {
  const initialized = openTeamSessionDatabase({ filename });
  let snapshot:
    | {
        outbox: Record<string, unknown>;
        sourceEvent: Record<string, unknown>;
        session: Record<string, unknown>;
      }
    | undefined;
  try {
    seedSessionAndAssignment(initialized.db);
    insertRuntimeRequestEvent(initialized.db, 1, "event:legacy-runtime-outbox", {
      commandId: "legacy-runtime-outbox-1",
      type: "runtime.session.ensure-requested",
    });
    initialized.db
      .prepare(
        `INSERT INTO runtime_outbox
           (id, session_id, session_sequence, kind, payload_json, status, attempts,
            lease_owner, lease_expires_at_ms, last_error, created_at_ms, delivered_at_ms)
         VALUES ('legacy-runtime-outbox-1', ?, 1, 'runtime.session.ensure', ?,
                 'pending', 3, NULL, NULL, 'retryable_transport_timeout', 100, NULL)`
      )
      .run(SESSION_ID, '{ "runtime": "legacy", "generation": 1 }');
    snapshot = {
      outbox: initialized.db
        .prepare(`SELECT * FROM runtime_outbox WHERE id = 'legacy-runtime-outbox-1'`)
        .get() as Record<string, unknown>,
      sourceEvent: initialized.db
        .prepare(`SELECT * FROM session_events WHERE event_id = 'event:legacy-runtime-outbox'`)
        .get() as Record<string, unknown>,
      session: initialized.db
        .prepare(`SELECT * FROM sessions WHERE id = ?`)
        .get(SESSION_ID) as Record<string, unknown>,
    };
  } finally {
    initialized.close();
  }
  const db = new Database(filename);
  try {
    db.exec(`
      DROP TRIGGER runtime_run_referenced_session_events_immutable_update;
      DROP TRIGGER runtime_run_referenced_session_events_immutable_delete;
      DROP TABLE runtime_run_command_effects;
      DROP TABLE runtime_run_command_receipts;
      DROP TABLE runtime_run_command_dispatch;
      DROP TABLE runtime_run_commands;
      PRAGMA user_version = 3;
    `);
  } finally {
    db.close();
  }
  if (!snapshot) throw new Error("Expected a v3 Runtime outbox fixture snapshot");
  return snapshot;
}

function createPopulatedRuntimeRunSchemaV4Fixture(filename: string): {
  run: Record<string, unknown>;
  command: Record<string, unknown>;
  dispatch: Record<string, unknown>;
  receipt: Record<string, unknown>;
  effect: Record<string, unknown>;
} {
  createRuntimeRunSchemaV4Fixture(filename);

  const db = new Database(filename);
  try {
    db.pragma("foreign_keys = ON");
    expect(db.pragma("user_version", { simple: true })).toBe(4);
    expect(
      (db.prepare(`PRAGMA table_info(agent_runs)`).all() as Array<{ name: string }>).map(
        ({ name }) => name
      )
    ).not.toContain("start_command_id");
    expect(
      (
        db.prepare(`PRAGMA table_info(runtime_run_command_dispatch)`).all() as Array<{
          name: string;
        }>
      ).map(({ name }) => name)
    ).not.toContain("available_at_ms");
    seedSessionAndAssignment(db);
    insertRun(db, "run-1", "active");
    insertRuntimeRequestEvent(db, 1, "event:pause-requested");
    insertRuntimeRunCommand(db, { skipDispatch: true });
    db.prepare(
      `INSERT INTO runtime_run_command_dispatch
         (command_id, agent_run_id, status, attempts, created_at_ms, updated_at_ms)
       VALUES ('runtime-command-1', 'run-1', 'pending', 0, 100, 100)`
    ).run();
    claimRuntimeRunDispatch(db, "runtime-command-1");
    insertRuntimeRunReceipt(db);
    insertRuntimeRequestEvent(db, 2, "event:pause-enforced", { type: "run.paused" });
    insertRuntimeRunEffect(db);
    db.prepare(
      `UPDATE agent_runs
       SET lifecycle = 'paused', state_version = 2, updated_at_ms = 115
       WHERE id = 'run-1'`
    ).run();
    terminalizeRuntimeRunDispatch(db, 120);

    return {
      run: db.prepare(`SELECT * FROM agent_runs WHERE id = 'run-1'`).get() as Record<
        string,
        unknown
      >,
      command: db
        .prepare(`SELECT * FROM runtime_run_commands WHERE id = 'runtime-command-1'`)
        .get() as Record<string, unknown>,
      dispatch: db
        .prepare(
          `SELECT * FROM runtime_run_command_dispatch WHERE command_id = 'runtime-command-1'`
        )
        .get() as Record<string, unknown>,
      receipt: db
        .prepare(`SELECT * FROM runtime_run_command_receipts WHERE id = 'receipt-1'`)
        .get() as Record<string, unknown>,
      effect: db
        .prepare(`SELECT * FROM runtime_run_command_effects WHERE command_id = 'runtime-command-1'`)
        .get() as Record<string, unknown>,
    };
  } finally {
    db.close();
  }
}

function createRuntimeRunSchemaV4DispatchFixture(
  filename: string,
  state:
    | "pending"
    | "processing-live"
    | "processing-expired"
    | "retried-pending"
    | "awaiting"
    | "accepted"
): void {
  createRuntimeRunSchemaV4Fixture(filename);
  const db = new Database(filename);
  try {
    db.pragma("foreign_keys = ON");
    seedSessionAndAssignment(db);
    insertRun(db, "run-1", "active");
    insertRuntimeRequestEvent(db, 1, "event:pause-requested");
    insertRuntimeRunCommand(db, { skipDispatch: true });
    db.prepare(
      `INSERT INTO runtime_run_command_dispatch
         (command_id, agent_run_id, status, attempts, created_at_ms, updated_at_ms)
       VALUES ('runtime-command-1', 'run-1', 'pending', 0, 100, 100)`
    ).run();
    if (state === "pending") return;

    claimRuntimeRunDispatch(db, "runtime-command-1");
    if (state === "processing-live") return;
    if (state === "processing-expired") {
      db.prepare(
        `UPDATE runtime_run_command_dispatch
         SET lease_expires_at_ms = updated_at_ms
         WHERE command_id = 'runtime-command-1'`
      ).run();
      return;
    }
    if (state === "retried-pending") {
      db.prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'pending', lease_owner = NULL, lease_expires_at_ms = NULL,
             last_safe_error_code = 'runtime_handle_unavailable', updated_at_ms = 102
         WHERE command_id = 'runtime-command-1'`
      ).run();
      return;
    }
    if (state === "accepted") {
      insertRuntimeRunReceipt(db, { outcome: "accepted" });
    }
    db.prepare(
      `UPDATE runtime_run_command_dispatch
       SET status = 'awaiting-receipt', lease_owner = NULL, lease_expires_at_ms = NULL,
           updated_at_ms = 110
       WHERE command_id = 'runtime-command-1'`
    ).run();
  } finally {
    db.close();
  }
}

function createRuntimeRunSchemaV4Fixture(filename: string): void {
  // Stop the real initializer at the exact committed v4 boundary. This avoids
  // maintaining a hand-copied approximation of the historical schema in the
  // test while still exercising v5 against a database that was genuinely
  // created by the v4 DDL.
  const pragmaDescriptor = Object.getOwnPropertyDescriptor(Database.prototype, "pragma");
  if (!pragmaDescriptor?.value) throw new Error("Expected better-sqlite3 pragma method");
  let stoppedAtVersionFour = false;
  Object.defineProperty(Database.prototype, "pragma", {
    ...pragmaDescriptor,
    value(this: Database.Database, source: string, ...args: unknown[]) {
      if (source === "foreign_keys = OFF") {
        stoppedAtVersionFour = true;
        throw new Error("stop-after-v4-for-migration-fixture");
      }
      return Reflect.apply(pragmaDescriptor.value, this, [source, ...args]);
    },
  });
  try {
    expect(() => openTeamSessionDatabase({ filename })).toThrow(
      /stop-after-v4-for-migration-fixture/
    );
  } finally {
    Object.defineProperty(Database.prototype, "pragma", pragmaDescriptor);
  }
  if (!stoppedAtVersionFour) throw new Error("Expected initializer to reach schema v4");
}
