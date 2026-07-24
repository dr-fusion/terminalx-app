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

  it("initializes the portable Phase 4 record set at schema v3", () => {
    database = openTeamSessionDatabase({ filename });

    expect(database.db.pragma("user_version", { simple: true })).toBe(3);
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
      ])
    );
    const sessionColumns = database.db.prepare("PRAGMA table_info(sessions)").all() as Array<{
      name: string;
    }>;
    expect(sessionColumns.map(({ name }) => name)).toContain("run_state_revision");
  });

  it("migrates a genuine v2 Session schema to v3 in one open", () => {
    createAgentRunSchemaV2Fixture(filename);

    database = openTeamSessionDatabase({ filename });

    expect(database.db.pragma("user_version", { simple: true })).toBe(3);
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
});

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

      PRAGMA application_id = 1415074609;
      PRAGMA user_version = 2;
    `);
  } finally {
    db.close();
  }
}
