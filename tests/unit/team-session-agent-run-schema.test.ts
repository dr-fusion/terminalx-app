import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  createTeamSessions,
  type SessionCommand,
} from "@/lib/team-sessions";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { createSqliteRuntimeLifecycleJournal } from "@/lib/team-sessions/sqlite-runtime-lifecycle-journal";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ASSIGNMENT_ID = "44444444-4444-4444-8444-444444444444";
const OTHER_SESSION_ID = "55555555-5555-4555-8555-555555555555";
const OTHER_ASSIGNMENT_ID = "66666666-6666-4666-8666-666666666666";
const EFFECT_ENFORCER_SET_DIGEST = "e".repeat(64);
const ENFORCEMENT_SUBJECT_DIGEST = "f".repeat(64);
const AGGREGATE_PROOF_DIGEST = "a".repeat(64);
const CONTAINMENT_ENFORCER_SET_DIGEST = "c".repeat(64);
const COMPENSATION_ENFORCEMENT_SUBJECT_DIGEST = "d".repeat(64);
const COMPENSATION_AGGREGATE_PROOF_DIGEST = "9".repeat(64);

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

  it("initializes the Agent Run, receipt-follow, compensation, and assignment interlock record set at schema v8", () => {
    database = openTeamSessionDatabase({ filename });

    expect(database.db.pragma("user_version", { simple: true })).toBe(8);
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
        "runtime_principal_observation_keys",
        "runtime_receipt_follow_streams",
        "runtime_receipt_follow_events",
        "runtime_binding_safety_fences",
        "runtime_compensation_incidents",
        "runtime_compensation_commands",
        "runtime_compensation_dispatch",
        "runtime_compensation_receipts",
        "runtime_compensation_effects",
        "runtime_compensation_follow_events",
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
    const assignmentOutboxColumns = database.db
      .prepare("PRAGMA table_info(runtime_outbox)")
      .all() as Array<{ name: string }>;
    expect(assignmentOutboxColumns.map(({ name }) => name)).toEqual(
      expect.arrayContaining(["dispatch_interlock_attempt", "dispatch_interlock_acquired_at_ms"])
    );
    expect(
      database.db
        .prepare(
          `SELECT name FROM sqlite_schema
           WHERE type = 'trigger' AND name LIKE 'runtime_outbox_dispatch_interlock_valid_%'
           ORDER BY name`
        )
        .all()
    ).toEqual([
      { name: "runtime_outbox_dispatch_interlock_valid_insert" },
      { name: "runtime_outbox_dispatch_interlock_valid_update" },
    ]);
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

  it("migrates a genuine v2 Session schema through v3, v4, v5, v6, v7, and v8 in one open", () => {
    createAgentRunSchemaV2Fixture(filename);

    database = openTeamSessionDatabase({ filename });

    expect(database.db.pragma("user_version", { simple: true })).toBe(8);
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

  it("accepts schema v8 when a peer finishes migration after this opener prepared v4", () => {
    createRuntimeRunSchemaV4Fixture(filename);
    const pragmaDescriptor = Object.getOwnPropertyDescriptor(Database.prototype, "pragma");
    if (!pragmaDescriptor?.value) throw new Error("Expected better-sqlite3 pragma method");
    let peerAdvanceStarted = false;
    let peerAdvanced = false;
    Object.defineProperty(Database.prototype, "pragma", {
      ...pragmaDescriptor,
      value(this: Database.Database, source: string, ...args: unknown[]) {
        if (!peerAdvanceStarted && source === "foreign_keys = OFF") {
          peerAdvanceStarted = true;
          const peer = openTeamSessionDatabase({ filename });
          try {
            expect(peer.db.pragma("user_version", { simple: true })).toBe(8);
            peerAdvanced = true;
          } finally {
            peer.close();
          }
        }
        return Reflect.apply(pragmaDescriptor.value, this, [source, ...args]);
      },
    });
    try {
      database = openTeamSessionDatabase({ filename });
    } finally {
      Object.defineProperty(Database.prototype, "pragma", pragmaDescriptor);
    }

    expect(peerAdvanceStarted).toBe(true);
    expect(peerAdvanced).toBe(true);
    expect(database.db.pragma("user_version", { simple: true })).toBe(8);
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
    expect(database.db.pragma("quick_check", { simple: true })).toBe("ok");
  });

  it("accepts schema v8 when a peer wins the v6 to v8 migration race", () => {
    createRuntimeCompensationSchemaV6Fixture(filename);
    const pragmaDescriptor = Object.getOwnPropertyDescriptor(Database.prototype, "pragma");
    if (!pragmaDescriptor?.value) throw new Error("Expected better-sqlite3 pragma method");
    let versionReads = 0;
    let peerAdvanced = false;
    Object.defineProperty(Database.prototype, "pragma", {
      ...pragmaDescriptor,
      value(this: Database.Database, source: string, ...args: unknown[]) {
        if (source === "user_version") {
          versionReads += 1;
          if (versionReads === 2) {
            const peer = openTeamSessionDatabase({ filename });
            try {
              expect(peer.db.pragma("user_version", { simple: true })).toBe(8);
              peerAdvanced = true;
            } finally {
              peer.close();
            }
          }
        }
        return Reflect.apply(pragmaDescriptor.value, this, [source, ...args]);
      },
    });
    try {
      database = openTeamSessionDatabase({ filename });
    } finally {
      Object.defineProperty(Database.prototype, "pragma", pragmaDescriptor);
    }

    expect(peerAdvanced).toBe(true);
    expect(database.db.pragma("user_version", { simple: true })).toBe(8);
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
  });

  it("upgrades an exact committed v7 database to v8 and marks attempted assignment work ambiguous", () => {
    createRuntimeAssignmentOutboxSchemaV7Fixture(filename);
    const legacy = new Database(filename);
    try {
      legacy.pragma("foreign_keys = ON");
      expect(legacy.pragma("user_version", { simple: true })).toBe(7);
      expect(hasColumn(legacy, "runtime_outbox", "dispatch_interlock_attempt")).toBe(false);
      expect(hasColumn(legacy, "runtime_outbox", "dispatch_interlock_acquired_at_ms")).toBe(false);
      expect(
        legacy
          .prepare(
            `SELECT COUNT(*) AS count FROM sqlite_schema
             WHERE type = 'trigger' AND name LIKE 'runtime_outbox_dispatch_interlock_valid_%'`
          )
          .get()
      ).toEqual({ count: 0 });

      seedSessionAndAssignment(legacy);
      insertRuntimeRequestEvent(legacy, 1, "event:v7-assignment-outbox", {
        commandId: "v7-assignment-outbox-1",
        type: "session.started",
        payload: {
          sessionId: SESSION_ID,
          runtimeKind: "local-tmux",
          runtimeAuthorizationGeneration: 1,
          enforcementState: "pending",
        },
      });
      legacy
        .prepare(
          `INSERT INTO runtime_outbox
             (id, session_id, session_sequence, kind, payload_json, status, attempts,
              lease_owner, lease_expires_at_ms, last_error, created_at_ms, delivered_at_ms)
           VALUES ('v7-assignment-outbox-1', ?, 1, 'runtime.session.ensure', ?,
                   'pending', 2, NULL, NULL, 'legacy_delivery_unknown', 100, NULL)`
        )
        .run(
          SESSION_ID,
          JSON.stringify({
            sessionId: SESSION_ID,
            runtimeKind: "local-tmux",
            tmuxName: "phase-four-schema",
            runtimeAuthorizationGeneration: 1,
          })
        );
    } finally {
      legacy.close();
    }

    database = openTeamSessionDatabase({ filename });

    expect(database.db.pragma("user_version", { simple: true })).toBe(8);
    expect(
      database.db
        .prepare(
          `SELECT dispatch_interlock_attempt, dispatch_interlock_acquired_at_ms
           FROM runtime_outbox WHERE id = 'v7-assignment-outbox-1'`
        )
        .get()
    ).toEqual({
      dispatch_interlock_attempt: 2,
      dispatch_interlock_acquired_at_ms: 100,
    });
    expect(
      database.db
        .prepare(
          `SELECT name FROM sqlite_schema
           WHERE type = 'trigger' AND name LIKE 'runtime_outbox_dispatch_interlock_valid_%'
           ORDER BY name`
        )
        .all()
    ).toEqual([
      { name: "runtime_outbox_dispatch_interlock_valid_insert" },
      { name: "runtime_outbox_dispatch_interlock_valid_update" },
    ]);
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
    expect(database.db.pragma("quick_check", { simple: true })).toBe("ok");
  });

  it("rolls back the entire v7 to v8 migration when legacy assignment lease state is invalid", () => {
    createRuntimeAssignmentOutboxSchemaV7Fixture(filename);
    const legacy = new Database(filename);
    try {
      legacy.pragma("foreign_keys = ON");
      seedSessionAndAssignment(legacy);
      insertRuntimeRequestEvent(legacy, 1, "event:v7-invalid-assignment-outbox", {
        commandId: "v7-invalid-assignment-outbox-1",
        type: "session.started",
        payload: {
          sessionId: SESSION_ID,
          runtimeKind: "local-tmux",
          runtimeAuthorizationGeneration: 1,
        },
      });
      legacy
        .prepare(
          `INSERT INTO runtime_outbox
             (id, session_id, session_sequence, kind, payload_json, status, attempts,
              lease_owner, lease_expires_at_ms, last_error, created_at_ms, delivered_at_ms)
           VALUES ('v7-invalid-assignment-outbox-1', ?, 1, 'runtime.session.ensure', ?,
                   'processing', 0, NULL, NULL, NULL, 100, NULL)`
        )
        .run(
          SESSION_ID,
          JSON.stringify({
            sessionId: SESSION_ID,
            runtimeKind: "local-tmux",
            tmuxName: "phase-four-schema",
            runtimeAuthorizationGeneration: 1,
          })
        );
    } finally {
      legacy.close();
    }

    expect(() => openTeamSessionDatabase({ filename })).toThrow(
      /Cannot migrate Runtime outbox v7-invalid-assignment-outbox-1: durable state is invalid/
    );

    const after = new Database(filename, { readonly: true });
    try {
      expect(after.pragma("user_version", { simple: true })).toBe(7);
      expect(hasColumn(after, "runtime_outbox", "dispatch_interlock_attempt")).toBe(false);
      expect(hasColumn(after, "runtime_outbox", "dispatch_interlock_acquired_at_ms")).toBe(false);
      expect(
        after
          .prepare(
            `SELECT COUNT(*) AS count FROM sqlite_schema
             WHERE type = 'trigger' AND name LIKE 'runtime_outbox_dispatch_interlock_valid_%'`
          )
          .get()
      ).toEqual({ count: 0 });
      expect(after.pragma("foreign_key_check")).toEqual([]);
      expect(after.pragma("quick_check", { simple: true })).toBe("ok");
    } finally {
      after.close();
    }
  });

  it.each([
    [
      "ensure",
      "runtime.session.ensure",
      {
        sessionId: SESSION_ID,
        runtimeKind: "local-tmux",
        tmuxName: "invalid tmux name",
        runtimeAuthorizationGeneration: 1,
      },
    ],
    [
      "fence",
      "runtime.authorization.fence",
      {
        sessionId: SESSION_ID,
        reason: "manager-loss",
        runtimeAuthorizationGeneration: 1,
      },
    ],
    [
      "retire",
      "runtime.session.retire",
      {
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 1,
        reason: "emergency-stop",
        agentRunId: "run-1",
        runtimeAssignmentId: ASSIGNMENT_ID,
        runtimeAssignmentGeneration: 0,
        sandboxId: "sandbox-1",
        sandboxGeneration: 1,
      },
    ],
    [
      "session-binding",
      "runtime.session.ensure",
      {
        sessionId: OTHER_SESSION_ID,
        runtimeKind: "local-tmux",
        tmuxName: "phase-four-schema",
        runtimeAuthorizationGeneration: 1,
      },
    ],
  ] as const)(
    "rejects a JSON-valid malformed v7 %s payload and rolls the v8 migration back",
    (fixtureName, kind, payload) => {
      createRuntimeAssignmentOutboxSchemaV7Fixture(filename);
      const outboxId = `v7-invalid-${fixtureName}-outbox`;
      const payloadJson = JSON.stringify(payload);
      const legacy = new Database(filename);
      try {
        legacy.pragma("foreign_keys = ON");
        seedSessionAndAssignment(legacy);
        insertRuntimeRequestEvent(legacy, 1, `event:${outboxId}`, {
          commandId: outboxId,
          type: "session.started",
          payload: {
            sessionId: SESSION_ID,
            runtimeKind: "local-tmux",
            runtimeAuthorizationGeneration: 1,
          },
        });
        legacy
          .prepare(
            `INSERT INTO runtime_outbox
               (id, session_id, session_sequence, kind, payload_json, status, attempts,
                lease_owner, lease_expires_at_ms, last_error, created_at_ms, delivered_at_ms)
             VALUES (?, ?, 1, ?, ?, 'pending', 0, NULL, NULL, NULL, 100, NULL)`
          )
          .run(outboxId, SESSION_ID, kind, payloadJson);
      } finally {
        legacy.close();
      }

      let migrationError: unknown;
      try {
        openTeamSessionDatabase({ filename });
      } catch (error) {
        migrationError = error;
      }
      expect(migrationError).toBeInstanceOf(Error);
      expect((migrationError as Error).message).toBe(
        `Cannot migrate Runtime outbox ${outboxId}: payload contract is invalid`
      );
      expect((migrationError as Error).message).not.toContain(payloadJson);

      const after = new Database(filename, { readonly: true });
      try {
        expect(after.pragma("user_version", { simple: true })).toBe(7);
        expect(hasColumn(after, "runtime_outbox", "dispatch_interlock_attempt")).toBe(false);
        expect(hasColumn(after, "runtime_outbox", "dispatch_interlock_acquired_at_ms")).toBe(false);
        expect(
          after
            .prepare(
              `SELECT kind, payload_json, status, attempts
               FROM runtime_outbox WHERE id = ?`
            )
            .get(outboxId)
        ).toEqual({ kind, payload_json: payloadJson, status: "pending", attempts: 0 });
        expect(
          after
            .prepare(
              `SELECT COUNT(*) AS count FROM sqlite_schema
               WHERE type = 'trigger' AND name LIKE 'runtime_outbox_%'`
            )
            .get()
        ).toEqual({ count: 0 });
        expect(after.pragma("foreign_key_check")).toEqual([]);
        expect(after.pragma("quick_check", { simple: true })).toBe("ok");
      } finally {
        after.close();
      }
    }
  );

  it.each([
    [
      "duplicate top-level key",
      "v7-duplicate-key-outbox",
      `{"sessionId":"${SESSION_ID}","sessionId":"${SESSION_ID}","runtimeKind":"local-tmux","tmuxName":"phase-four-schema","runtimeAuthorizationGeneration":1}`,
    ],
    [
      "decimal integer lookalike",
      "v7-decimal-generation-outbox",
      `{"sessionId":"${SESSION_ID}","runtimeKind":"local-tmux","tmuxName":"phase-four-schema","runtimeAuthorizationGeneration":1.0}`,
    ],
    [
      "exponent integer lookalike",
      "v7-exponent-generation-outbox",
      `{"sessionId":"${SESSION_ID}","runtimeKind":"local-tmux","tmuxName":"phase-four-schema","runtimeAuthorizationGeneration":1e0}`,
    ],
  ] as const)(
    "rejects a v7 payload with a %s and rolls migration back",
    (_, outboxId, payloadJson) => {
      seedRuntimeOutboxV7Fixture(filename, { outboxId, payloadJson });

      expectRuntimeOutboxV7MigrationRollback(filename, {
        outboxId,
        expectedError: `Cannot migrate Runtime outbox ${outboxId}: payload contract is invalid`,
        payloadJson,
      });
    }
  );

  it("rejects an emergency identifier whose non-BMP text exceeds 300 UTF-8 bytes", () => {
    const oversizedIdentifier = "🧨".repeat(76);
    expect(oversizedIdentifier.length).toBeLessThanOrEqual(300);
    expect(Buffer.byteLength(oversizedIdentifier, "utf8")).toBeGreaterThan(300);
    const outboxId = "v7-oversized-emergency-identifier-outbox";
    const payloadJson = JSON.stringify({
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: 1,
      reason: "emergency-stop",
      agentRunId: oversizedIdentifier,
      runtimeAssignmentId: ASSIGNMENT_ID,
      runtimeAssignmentGeneration: 1,
      sandboxId: "sandbox-1",
      sandboxGeneration: 1,
    });
    seedRuntimeOutboxV7Fixture(filename, {
      outboxId,
      kind: "runtime.session.retire",
      payloadJson,
    });

    expectRuntimeOutboxV7MigrationRollback(filename, {
      outboxId,
      expectedError: `Cannot migrate Runtime outbox ${outboxId}: payload contract is invalid`,
      payloadJson,
    });
  });

  it.each([
    {
      caseName: "processing delivery timestamp",
      outboxId: "v7-processing-delivered-outbox",
      status: "processing",
      attempts: 1,
      leaseOwner: "worker-1",
      leaseExpiresAtMs: 500,
      deliveredAtMs: 101,
    },
    {
      caseName: "empty processing owner",
      outboxId: "v7-empty-owner-outbox",
      status: "processing",
      attempts: 1,
      leaseOwner: "",
      leaseExpiresAtMs: 500,
    },
    {
      caseName: "oversized processing owner",
      outboxId: "v7-oversized-owner-outbox",
      status: "processing",
      attempts: 1,
      leaseOwner: "w".repeat(301),
      leaseExpiresAtMs: 500,
    },
    {
      caseName: "pending lease",
      outboxId: "v7-pending-lease-outbox",
      status: "pending",
      attempts: 0,
      leaseOwner: "worker-1",
      leaseExpiresAtMs: 500,
    },
    {
      caseName: "pending delivery timestamp",
      outboxId: "v7-pending-delivered-outbox",
      status: "pending",
      attempts: 0,
      deliveredAtMs: 101,
    },
    {
      caseName: "unsafe attempt count",
      outboxId: "v7-unsafe-attempts-outbox",
      status: "pending",
      attempts: Number.MAX_SAFE_INTEGER + 1,
    },
    {
      caseName: "unsafe creation timestamp",
      outboxId: "v7-unsafe-created-at-outbox",
      status: "pending",
      attempts: 0,
      createdAtMs: Number.MAX_SAFE_INTEGER + 1,
    },
    {
      caseName: "unsafe processing lease timestamp",
      outboxId: "v7-unsafe-lease-expiry-outbox",
      status: "processing",
      attempts: 1,
      leaseOwner: "worker-1",
      leaseExpiresAtMs: Number.MAX_SAFE_INTEGER + 1,
    },
    {
      caseName: "unsafe delivered timestamp",
      outboxId: "v7-unsafe-delivered-at-outbox",
      status: "delivered",
      attempts: 1,
      deliveredAtMs: Number.MAX_SAFE_INTEGER + 1,
    },
  ] as const)("rejects v7 durable-state poison: $caseName", (fixture) => {
    seedRuntimeOutboxV7Fixture(filename, fixture);

    expectRuntimeOutboxV7MigrationRollback(filename, {
      outboxId: fixture.outboxId,
      expectedError: `Cannot migrate Runtime outbox ${fixture.outboxId}: durable state is invalid`,
    });
  });

  it("rejects a mismatched v7 source event and rolls migration back", () => {
    const outboxId = "v7-mismatched-source-outbox";
    seedRuntimeOutboxV7Fixture(filename, {
      outboxId,
      eventPayload: {
        sessionId: SESSION_ID,
        runtimeKind: "local-tmux",
        runtimeAuthorizationGeneration: 2,
      },
    });

    expectRuntimeOutboxV7MigrationRollback(filename, {
      outboxId,
      expectedError: `Cannot migrate Runtime outbox ${outboxId}: source event is invalid`,
    });
  });

  it("rejects duplicate relevant keys in a v7 source event and rolls migration back", () => {
    const outboxId = "v7-duplicate-source-generation-outbox";
    seedRuntimeOutboxV7Fixture(filename, {
      outboxId,
      eventPayloadJson: `{"sessionId":"${SESSION_ID}","runtimeKind":"local-tmux","runtimeAuthorizationGeneration":1,"runtimeAuthorizationGeneration":1}`,
    });

    expectRuntimeOutboxV7MigrationRollback(filename, {
      outboxId,
      expectedError: `Cannot migrate Runtime outbox ${outboxId}: source event is invalid`,
    });
  });

  it("rejects a fresh Runtime outbox whose source event does not match", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db, { runtimeAuthorizationState: "pending" });
    insertRuntimeRequestEvent(database.db, 1, "event:fresh-mismatched-source", {
      type: "session.started",
      payload: {
        sessionId: SESSION_ID,
        runtimeKind: "local-tmux",
        runtimeAuthorizationGeneration: 2,
      },
    });
    const payloadJson = JSON.stringify({
      sessionId: SESSION_ID,
      runtimeKind: "local-tmux",
      tmuxName: "phase-four-schema",
      runtimeAuthorizationGeneration: 1,
    });

    expect(() =>
      database!.db
        .prepare(
          `INSERT INTO runtime_outbox
             (id, session_id, session_sequence, kind, payload_json,
              status, attempts, created_at_ms)
           VALUES ('fresh-mismatched-source-outbox', ?, 1,
                   'runtime.session.ensure', ?, 'pending', 0, 100)`
        )
        .run(SESSION_ID, payloadJson)
    ).toThrow(/Runtime outbox source event does not match/);
    expect(database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_outbox`).get()).toEqual({
      count: 0,
    });
    expect(
      database.db
        .prepare(`SELECT event_id FROM session_events WHERE session_id = ? AND sequence = 1`)
        .get(SESSION_ID)
    ).toEqual({ event_id: "event:fresh-mismatched-source" });
  });

  it("rejects a fresh Runtime outbox whose source event has duplicate relevant keys", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db, { runtimeAuthorizationState: "pending" });
    const duplicateSourceJson = `{"sessionId":"${SESSION_ID}","runtimeKind":"local-tmux","runtimeAuthorizationGeneration":1,"runtimeAuthorizationGeneration":1}`;
    database.db
      .prepare(
        `INSERT INTO session_events
           (session_id, sequence, event_id, type, occurred_at_ms,
            actor_kind, actor_user_id, actor_display_name,
            source_scope, source_key, payload_json)
         VALUES (?, 1, 'event:fresh-duplicate-source', 'session.started', 100,
                 'system', 'source-fixture', 'Source Fixture',
                 'vitest:source-fixture', 'fresh-duplicate-source', ?)`
      )
      .run(SESSION_ID, duplicateSourceJson);
    const payloadJson = JSON.stringify({
      sessionId: SESSION_ID,
      runtimeKind: "local-tmux",
      tmuxName: "phase-four-schema",
      runtimeAuthorizationGeneration: 1,
    });

    expect(() =>
      database!.db
        .prepare(
          `INSERT INTO runtime_outbox
             (id, session_id, session_sequence, kind, payload_json,
              status, attempts, created_at_ms)
           VALUES ('fresh-duplicate-source-outbox', ?, 1,
                   'runtime.session.ensure', ?, 'pending', 0, 100)`
        )
        .run(SESSION_ID, payloadJson)
    ).toThrow(/Runtime outbox source event does not match/);
    expect(database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_outbox`).get()).toEqual({
      count: 0,
    });
    expect(
      database.db
        .prepare(
          `SELECT payload_json FROM session_events
           WHERE event_id = 'event:fresh-duplicate-source'`
        )
        .get()
    ).toEqual({ payload_json: duplicateSourceJson });
  });

  it("makes Runtime outbox work immutable and permits only kernel state transitions", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db, { runtimeAuthorizationState: "pending" });
    const db = database.db;
    const ensurePayload = JSON.stringify({
      sessionId: SESSION_ID,
      runtimeKind: "local-tmux",
      tmuxName: "phase-four-schema",
      runtimeAuthorizationGeneration: 1,
    });
    const insertPendingOutbox = (id: string, sequence: number): void => {
      insertRuntimeRequestEvent(db, sequence, `event:${id}`, {
        commandId: id,
        type: "session.started",
        payload: {
          sessionId: SESSION_ID,
          runtimeKind: "local-tmux",
          runtimeAuthorizationGeneration: 1,
        },
      });
      db.prepare(
        `INSERT INTO runtime_outbox
           (id, session_id, session_sequence, kind, payload_json, status, attempts, created_at_ms)
         VALUES (?, ?, ?, 'runtime.session.ensure', ?, 'pending', 0, 100)`
      ).run(id, SESSION_ID, sequence, ensurePayload);
    };

    insertPendingOutbox("outbox-state-1", 1);
    insertRuntimeRequestEvent(db, 2, "event:outbox-marker-insert", {
      commandId: "outbox-marker-insert",
      type: "session.started",
      payload: {
        sessionId: SESSION_ID,
        runtimeKind: "local-tmux",
        runtimeAuthorizationGeneration: 1,
      },
    });
    const malformedV8Payload = JSON.stringify({
      sessionId: SESSION_ID,
      runtimeKind: "local-tmux",
      tmuxName: "phase-four-schema",
      runtimeAuthorizationGeneration: 1,
      untrustedExtraField: "must-not-enter-the-ordered-outbox",
    });
    let insertError: unknown;
    try {
      db.prepare(
        `INSERT INTO runtime_outbox
           (id, session_id, session_sequence, kind, payload_json, status, attempts, created_at_ms)
         VALUES ('outbox-payload-insert', ?, 2, 'runtime.session.ensure', ?, 'pending', 0, 100)`
      ).run(SESSION_ID, malformedV8Payload);
    } catch (error) {
      insertError = error;
    }
    expect(insertError).toBeInstanceOf(Error);
    expect((insertError as Error).message).toContain("Runtime outbox payload contract is invalid");
    expect((insertError as Error).message).not.toContain(malformedV8Payload);
    expect(() =>
      db
        .prepare(
          `INSERT INTO runtime_outbox
             (id, session_id, session_sequence, kind, payload_json, status, attempts,
              lease_owner, lease_expires_at_ms, dispatch_interlock_attempt,
              dispatch_interlock_acquired_at_ms, created_at_ms)
           VALUES ('outbox-marker-insert', ?, 2, 'runtime.session.ensure', ?,
                   'processing', 1, 'worker-1', 500, 1, 101, 100)`
        )
        .run(SESSION_ID, ensurePayload)
    ).toThrow(/must begin in the exact pending state/);

    for (const [
      name,
      status,
      attempts,
      leaseOwner,
      leaseExpiry,
      markerAttempt,
      markerAt,
      error,
      deliveredAt,
    ] of [
      ["status", "delivered", 0, null, null, null, null, null, 101],
      ["attempts", "pending", 1, null, null, null, null, null, null],
      ["lease owner", "pending", 0, "worker-1", null, null, null, null, null],
      ["lease expiry", "pending", 0, null, 500, null, null, null, null],
      ["marker attempt", "pending", 0, null, null, 1, null, null, null],
      ["marker time", "pending", 0, null, null, null, 101, null, null],
      ["last error", "pending", 0, null, null, null, null, "fabricated", null],
      ["delivered time", "pending", 0, null, null, null, null, null, 101],
    ] as const) {
      expect(() =>
        db
          .prepare(
            `INSERT INTO runtime_outbox
                 (id, session_id, session_sequence, kind, payload_json, status, attempts,
                  lease_owner, lease_expires_at_ms, dispatch_interlock_attempt,
                  dispatch_interlock_acquired_at_ms, last_error, delivered_at_ms, created_at_ms)
               VALUES (?, ?, 2, 'runtime.session.ensure', ?, ?, ?, ?, ?, ?, ?, ?, ?, 100)`
          )
          .run(
            `outbox-invalid-initial-${name.replaceAll(" ", "-")}`,
            SESSION_ID,
            ensurePayload,
            status,
            attempts,
            leaseOwner,
            leaseExpiry,
            markerAttempt,
            markerAt,
            error,
            deliveredAt
          )
      ).toThrow(/must begin in the exact pending state/);
    }

    for (const [column, value] of [
      ["id", "'outbox-retargeted'"],
      ["session_id", `'${OTHER_SESSION_ID}'`],
      ["session_sequence", "99"],
      ["kind", "'runtime.authorization.fence'"],
      [
        "payload_json",
        `'${JSON.stringify({
          sessionId: SESSION_ID,
          runtimeKind: "local-tmux",
          tmuxName: "retargeted",
          runtimeAuthorizationGeneration: 1,
        })}'`,
      ],
      ["created_at_ms", "101"],
    ] as const) {
      expect(() =>
        db
          .prepare(`UPDATE runtime_outbox SET ${column} = ${value} WHERE id = 'outbox-state-1'`)
          .run()
      ).toThrow(/identity and work are immutable/);
    }
    expect(() =>
      db
        .prepare(
          `UPDATE session_events SET event_id = 'event:retargeted'
           WHERE session_id = ? AND sequence = 1`
        )
        .run(SESSION_ID)
    ).toThrow(/Runtime outbox source events are immutable/);
    expect(() =>
      db.prepare(`DELETE FROM runtime_outbox WHERE id = 'outbox-state-1'`).run()
    ).toThrow(/Runtime outbox rows are immutable/);

    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'delivered', delivered_at_ms = 101
           WHERE id = 'outbox-state-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime outbox state transition/);
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'failed', last_error = 'fabricated_failure'
           WHERE id = 'outbox-state-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime outbox state transition/);
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'processing', attempts = 1, lease_expires_at_ms = 500
           WHERE id = 'outbox-state-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime outbox state transition/);

    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'processing', attempts = 1,
               lease_owner = 'worker-1', lease_expires_at_ms = 500
           WHERE id = 'outbox-state-1'`
        )
        .run()
    ).not.toThrow();
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET dispatch_interlock_attempt = 1, dispatch_interlock_acquired_at_ms = 101
           WHERE id = 'outbox-state-1'`
        )
        .run()
    ).not.toThrow();
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox SET lease_expires_at_ms = 600
           WHERE id = 'outbox-state-1'`
        )
        .run()
    ).not.toThrow();
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'pending', lease_owner = NULL, lease_expires_at_ms = NULL
           WHERE id = 'outbox-state-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime outbox state transition/);
    db.prepare(
      `INSERT INTO runtime_outbox_settlements
         (outbox_id, attempt, lease_owner, lease_expires_at_ms,
          dispatch_interlock_attempt, dispatch_interlock_acquired_at_ms,
          outcome, error_code, command_source_scope, command_source_key, recorded_at_ms)
       VALUES ('outbox-state-1', 1, 'worker-1', 600, 1, 101,
               'lease-expired', NULL, NULL, NULL, 600)`
    ).run();
    db.prepare(
      `UPDATE runtime_outbox
       SET status = 'pending', lease_owner = NULL, lease_expires_at_ms = NULL
       WHERE id = 'outbox-state-1'`
    ).run();
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'processing', attempts = 2,
               lease_owner = 'worker-2', lease_expires_at_ms = 700
           WHERE id = 'outbox-state-1'`
        )
        .run()
    ).not.toThrow();
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'delivered', lease_owner = NULL, lease_expires_at_ms = NULL,
               delivered_at_ms = 200, last_error = NULL
           WHERE id = 'outbox-state-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime outbox state transition/);
    db.transaction(() => {
      db.prepare(
        `INSERT INTO runtime_outbox_settlements
           (outbox_id, attempt, lease_owner, lease_expires_at_ms,
            dispatch_interlock_attempt, dispatch_interlock_acquired_at_ms,
            outcome, error_code, command_source_scope, command_source_key, recorded_at_ms)
         VALUES ('outbox-state-1', 2, 'worker-2', 700, 1, 101,
                 'acknowledged', NULL, 'vitest:evidence', 'ack-state-1', 200)`
      ).run();
      db.prepare(
        `UPDATE runtime_outbox
         SET status = 'delivered', lease_owner = NULL, lease_expires_at_ms = NULL,
             delivered_at_ms = 200, last_error = NULL
         WHERE id = 'outbox-state-1'`
      ).run();
      insertAcceptedRuntimeOutboxCommand(db, {
        acceptedSequence: 1,
        sourceKey: "ack-state-1",
        commandType: "runtime.outbox.acknowledge",
        workerId: "worker-2",
        outboxId: "outbox-state-1",
        attempt: 2,
        leaseExpiresAtMs: 700,
      });
    }).immediate();
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'pending', delivered_at_ms = NULL
           WHERE id = 'outbox-state-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime outbox state transition/);

    insertPendingOutbox("outbox-state-2", 3);
    db.prepare(
      `UPDATE runtime_outbox
       SET status = 'processing', attempts = 1,
           lease_owner = 'worker-1', lease_expires_at_ms = 500
       WHERE id = 'outbox-state-2'`
    ).run();
    db.prepare(
      `UPDATE runtime_outbox
       SET dispatch_interlock_attempt = 1, dispatch_interlock_acquired_at_ms = 101
       WHERE id = 'outbox-state-2'`
    ).run();
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'failed', lease_owner = NULL, lease_expires_at_ms = NULL,
               last_error = 'runtime_internal'
           WHERE id = 'outbox-state-2'`
        )
        .run()
    ).toThrow(/Invalid Runtime outbox state transition/);
    db.transaction(() => {
      db.prepare(
        `INSERT INTO runtime_outbox_settlements
           (outbox_id, attempt, lease_owner, lease_expires_at_ms,
            dispatch_interlock_attempt, dispatch_interlock_acquired_at_ms,
            outcome, error_code, command_source_scope, command_source_key, recorded_at_ms)
         VALUES ('outbox-state-2', 1, 'worker-1', 500, 1, 101,
                 'terminal-failure', 'runtime_internal',
                 'vitest:evidence', 'fail-state-2', 200)`
      ).run();
      db.prepare(
        `UPDATE runtime_outbox
         SET status = 'failed', lease_owner = NULL, lease_expires_at_ms = NULL,
             last_error = 'runtime_internal'
         WHERE id = 'outbox-state-2'`
      ).run();
      insertAcceptedRuntimeOutboxCommand(db, {
        acceptedSequence: 2,
        sourceKey: "fail-state-2",
        commandType: "runtime.outbox.fail",
        workerId: "worker-1",
        outboxId: "outbox-state-2",
        attempt: 1,
        leaseExpiresAtMs: 500,
        retryable: false,
        errorCode: "runtime_internal",
      });
    }).immediate();
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'processing', attempts = 2,
               lease_owner = 'worker-2', lease_expires_at_ms = 700
           WHERE id = 'outbox-state-2'`
        )
        .run()
    ).toThrow(/Invalid Runtime outbox state transition/);

    db.prepare(
      `UPDATE sessions
       SET runtime_authorization_generation = 2, runtime_authorization_state = 'quarantined'
       WHERE id = ?`
    ).run(SESSION_ID);
    db.prepare(
      `UPDATE runtime_assignments
       SET runtime_authorization_generation = 2, status = 'quarantined'
       WHERE id = ?`
    ).run(ASSIGNMENT_ID);
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox SET status = 'superseded', delivered_at_ms = 300
           WHERE id = 'outbox-state-2'`
        )
        .run()
    ).toThrow(/Invalid Runtime outbox state transition/);

    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox_settlements SET recorded_at_ms = 201
           WHERE outbox_id = 'outbox-state-1' AND attempt = 2`
        )
        .run()
    ).toThrow(/settlements are immutable/);
    expect(() =>
      db
        .prepare(
          `DELETE FROM runtime_outbox_settlements
           WHERE outbox_id = 'outbox-state-1' AND attempt = 2`
        )
        .run()
    ).toThrow(/settlements are immutable/);
    expect(() =>
      db
        .prepare(
          `UPDATE accepted_commands SET accepted_at_ms = 201
           WHERE source_scope = 'vitest:evidence' AND source_key = 'ack-state-1'`
        )
        .run()
    ).toThrow(/Accepted commands are immutable/);
    expect(() =>
      db
        .prepare(
          `DELETE FROM accepted_commands
           WHERE source_scope = 'vitest:evidence' AND source_key = 'ack-state-1'`
        )
        .run()
    ).toThrow(/Accepted commands are immutable/);

    expect(
      db
        .prepare(
          `SELECT id, status, attempts, dispatch_interlock_attempt
           FROM runtime_outbox ORDER BY id`
        )
        .all()
    ).toEqual([
      {
        id: "outbox-state-1",
        status: "delivered",
        attempts: 2,
        dispatch_interlock_attempt: 1,
      },
      {
        id: "outbox-state-2",
        status: "failed",
        attempts: 1,
        dispatch_interlock_attempt: 1,
      },
    ]);
  });

  it("requires per-target evidence for supersession and keeps that evidence immutable", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db, { runtimeAuthorizationState: "pending" });
    const db = database.db;
    const targetPayloadJson = JSON.stringify({
      sessionId: SESSION_ID,
      runtimeKind: "local-tmux",
      tmuxName: "phase-four-schema",
      runtimeAuthorizationGeneration: 1,
    });
    insertRuntimeRequestEvent(db, 1, "event:evidence-target", {
      type: "session.started",
      payload: {
        sessionId: SESSION_ID,
        runtimeKind: "local-tmux",
        runtimeAuthorizationGeneration: 1,
      },
    });
    db.prepare(
      `INSERT INTO runtime_outbox
         (id, session_id, session_sequence, kind, payload_json,
          status, attempts, created_at_ms)
       VALUES ('evidence-target-outbox', ?, 1, 'runtime.session.ensure', ?,
               'pending', 0, 100)`
    ).run(SESSION_ID, targetPayloadJson);

    for (const mutation of [
      `UPDATE runtime_outbox
       SET status = 'delivered', delivered_at_ms = 300
       WHERE id = 'evidence-target-outbox'`,
      `UPDATE runtime_outbox
       SET status = 'failed', last_error = 'runtime_internal'
       WHERE id = 'evidence-target-outbox'`,
      `UPDATE runtime_outbox
       SET status = 'superseded', delivered_at_ms = 300
       WHERE id = 'evidence-target-outbox'`,
    ]) {
      expect(() => db.prepare(mutation).run()).toThrow(/Invalid Runtime outbox state transition/);
    }

    insertRun(db, "run-1", "active");
    if (hasColumn(db, "runtime_authorization_epochs", "effect_enforcer_set_digest")) {
      db.prepare(
        `INSERT INTO runtime_authorization_epochs
           (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms,
            effect_enforcer_set_digest)
         VALUES (?, 2, ?, 1, 'sandbox-1', 1, 'principal-1', 200, ?)`
      ).run(SESSION_ID, ASSIGNMENT_ID, EFFECT_ENFORCER_SET_DIGEST);
    } else {
      db.prepare(
        `INSERT INTO runtime_authorization_epochs
           (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms)
         VALUES (?, 2, ?, 1, 'sandbox-1', 1, 'principal-1', 200)`
      ).run(SESSION_ID, ASSIGNMENT_ID);
    }
    db.prepare(
      `UPDATE sessions
       SET runtime_authorization_generation = 2, runtime_authorization_state = 'quarantined'
       WHERE id = ?`
    ).run(SESSION_ID);
    db.prepare(
      `UPDATE runtime_assignments
       SET runtime_authorization_generation = 2, status = 'quarantined'
       WHERE id = ?`
    ).run(ASSIGNMENT_ID);
    db.prepare(
      `UPDATE agent_runs
       SET lifecycle = 'pausing', state_version = 2,
           runtime_authorization_generation = 2, updated_at_ms = 200
       WHERE id = 'run-1'`
    ).run();

    const evidenceSourceKey = "event:evidence-emergency-source";
    insertRuntimeRequestEvent(db, 2, evidenceSourceKey, {
      type: "run.emergency-stop.requested",
      payload: {
        agentRunId: "run-1",
        runtimeAuthorizationGeneration: 2,
        reason: "Unexpected production target",
        revokeAllRunGrants: true,
      },
    });
    const sourcePayloadJson = JSON.stringify({
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: 2,
      reason: "emergency-stop",
      agentRunId: "run-1",
      runtimeAssignmentId: ASSIGNMENT_ID,
      runtimeAssignmentGeneration: 1,
      sandboxId: "sandbox-1",
      sandboxGeneration: 1,
    });
    db.prepare(
      `INSERT INTO runtime_outbox
         (id, session_id, session_sequence, kind, payload_json,
          status, attempts, created_at_ms)
       VALUES ('evidence-emergency-source', ?, 2, 'runtime.session.retire', ?,
               'pending', 0, 100)`
    ).run(SESSION_ID, sourcePayloadJson);

    db.transaction(() => {
      db.prepare(
        `INSERT INTO runtime_outbox_supersession_evidence
           (target_outbox_id, source_outbox_id, reason,
            target_status, target_attempts, target_lease_owner,
            target_lease_expires_at_ms, target_dispatch_interlock_attempt,
            target_dispatch_interlock_acquired_at_ms,
            source_attempts, source_lease_owner, source_lease_expires_at_ms,
            source_dispatch_interlock_attempt, source_dispatch_interlock_acquired_at_ms,
            command_source_scope, command_source_key, recorded_at_ms)
         VALUES ('evidence-target-outbox', 'evidence-emergency-source', 'emergency-cutover',
                 'pending', 0, NULL, NULL, NULL, NULL,
                 0, NULL, NULL, NULL, NULL,
                 'vitest:runtime-command', ?, 100)`
      ).run(evidenceSourceKey);
      db.prepare(
        `INSERT INTO accepted_commands
           (source_scope, source_key, payload_digest, accepted_sequence, command_type,
            actor_kind, actor_user_id, actor_display_name, payload_json, result_json,
            secret_result, accepted_at_ms)
         VALUES ('vitest:runtime-command', ?, ?, 1, 'run.emergency-stop',
                 'human', 'user-alice', 'Alice', ?, '{}', 0, 100)`
      ).run(
        evidenceSourceKey,
        digestFor("accepted:evidence-emergency-source"),
        JSON.stringify({
          type: "run.emergency-stop",
          sessionId: SESSION_ID,
          agentRunId: "run-1",
          reason: "Unexpected production target",
          revokeAllRunGrants: true,
          runtimeBinding: {
            runtimeAssignmentId: ASSIGNMENT_ID,
            runtimeAssignmentGeneration: 1,
            sandboxId: "sandbox-1",
            sandboxGeneration: 1,
          },
        })
      );
    }).immediate();

    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox
           SET status = 'superseded', delivered_at_ms = 100
           WHERE id = 'evidence-target-outbox'`
        )
        .run()
    ).not.toThrow();
    expect(() =>
      db
        .prepare(
          `UPDATE runtime_outbox_supersession_evidence SET recorded_at_ms = 101
           WHERE target_outbox_id = 'evidence-target-outbox'`
        )
        .run()
    ).toThrow(/supersession evidence is immutable/);
    expect(() =>
      db
        .prepare(
          `DELETE FROM runtime_outbox_supersession_evidence
           WHERE target_outbox_id = 'evidence-target-outbox'`
        )
        .run()
    ).toThrow(/supersession evidence is immutable/);
    expect(() =>
      db
        .prepare(
          `UPDATE accepted_commands SET accepted_at_ms = 101
           WHERE source_scope = 'vitest:runtime-command' AND source_key = ?`
        )
        .run(evidenceSourceKey)
    ).toThrow(/Accepted commands are immutable/);
    expect(() =>
      db
        .prepare(
          `DELETE FROM accepted_commands
           WHERE source_scope = 'vitest:runtime-command' AND source_key = ?`
        )
        .run(evidenceSourceKey)
    ).toThrow(/Accepted commands are immutable/);
    expect(
      db
        .prepare(
          `SELECT status, delivered_at_ms FROM runtime_outbox
           WHERE id = 'evidence-target-outbox'`
        )
        .get()
    ).toEqual({ status: "superseded", delivered_at_ms: 100 });
  });

  it.each([
    {
      caseName: "missing expectedAttempt",
      payloadJson: JSON.stringify({
        type: "runtime.outbox.acknowledge",
        outboxId: "malformed-ack-outbox",
        workerId: "worker-1",
        expectedLeaseExpiresAtMs: 500,
      }),
    },
    {
      caseName: "string expectedAttempt",
      payloadJson: JSON.stringify({
        type: "runtime.outbox.acknowledge",
        outboxId: "malformed-ack-outbox",
        workerId: "worker-1",
        expectedAttempt: "1",
        expectedLeaseExpiresAtMs: 500,
      }),
    },
    {
      caseName: "duplicate outboxId",
      payloadJson: `{"type":"runtime.outbox.acknowledge","outboxId":"malformed-ack-outbox","outboxId":"malformed-ack-outbox","workerId":"worker-1","expectedAttempt":1,"expectedLeaseExpiresAtMs":500}`,
    },
  ] as const)(
    "rolls back acknowledgement settlement evidence for an accepted payload with $caseName",
    ({ caseName, payloadJson }) => {
      database = openTeamSessionDatabase({ filename });
      const db = database.db;
      seedRuntimeOutboxAcknowledgementEvidenceFixture(db);
      const sourceKey = `malformed-ack-${caseName.replaceAll(" ", "-")}`;

      expect(() =>
        db
          .transaction(() => {
            db.prepare(
              `INSERT INTO runtime_outbox_settlements
                 (outbox_id, attempt, lease_owner, lease_expires_at_ms,
                  dispatch_interlock_attempt, dispatch_interlock_acquired_at_ms,
                  outcome, error_code, command_source_scope, command_source_key,
                  recorded_at_ms)
               VALUES ('malformed-ack-outbox', 1, 'worker-1', 500, 1, 101,
                       'acknowledged', NULL, 'vitest:malformed-evidence', ?, 200)`
            ).run(sourceKey);
            db.prepare(
              `INSERT INTO accepted_commands
                 (source_scope, source_key, payload_digest, accepted_sequence, command_type,
                  actor_kind, actor_user_id, actor_display_name, payload_json, result_json,
                  secret_result, accepted_at_ms)
               VALUES ('vitest:malformed-evidence', ?, ?, 1,
                       'runtime.outbox.acknowledge', 'system', 'worker-1',
                       'Runtime Worker', ?, '{}', 0, 200)`
            ).run(sourceKey, digestFor(`accepted:${sourceKey}`), payloadJson);
          })
          .immediate()
      ).toThrow(/Accepted command does not match Runtime outbox evidence/);
      expect(
        db
          .prepare(
            `SELECT COUNT(*) AS count FROM runtime_outbox_settlements
             WHERE outbox_id = 'malformed-ack-outbox'`
          )
          .get()
      ).toEqual({ count: 0 });
      expect(
        db
          .prepare(
            `SELECT COUNT(*) AS count FROM accepted_commands
             WHERE source_scope = 'vitest:malformed-evidence' AND source_key = ?`
          )
          .get(sourceKey)
      ).toEqual({ count: 0 });
      expect(
        db
          .prepare(
            `SELECT status, attempts, lease_owner, lease_expires_at_ms,
                    dispatch_interlock_attempt, dispatch_interlock_acquired_at_ms
             FROM runtime_outbox WHERE id = 'malformed-ack-outbox'`
          )
          .get()
      ).toEqual({
        status: "processing",
        attempts: 1,
        lease_owner: "worker-1",
        lease_expires_at_ms: 500,
        dispatch_interlock_attempt: 1,
        dispatch_interlock_acquired_at_ms: 101,
      });
    }
  );

  it.each([
    {
      caseName: "missing nested sandboxGeneration",
      payloadJson: JSON.stringify({
        type: "run.emergency-stop",
        sessionId: SESSION_ID,
        agentRunId: "run-1",
        reason: "Unexpected production target",
        revokeAllRunGrants: true,
        runtimeBinding: {
          runtimeAssignmentId: ASSIGNMENT_ID,
          runtimeAssignmentGeneration: 1,
          sandboxId: "sandbox-1",
        },
      }),
    },
    {
      caseName: "string nested assignment generation",
      payloadJson: JSON.stringify({
        type: "run.emergency-stop",
        sessionId: SESSION_ID,
        agentRunId: "run-1",
        reason: "Unexpected production target",
        revokeAllRunGrants: true,
        runtimeBinding: {
          runtimeAssignmentId: ASSIGNMENT_ID,
          runtimeAssignmentGeneration: "1",
          sandboxId: "sandbox-1",
          sandboxGeneration: 1,
        },
      }),
    },
    {
      caseName: "duplicate top-level agentRunId",
      payloadJson: `{"type":"run.emergency-stop","sessionId":"${SESSION_ID}","agentRunId":"run-1","agentRunId":"run-1","reason":"Unexpected production target","revokeAllRunGrants":true,"runtimeBinding":{"runtimeAssignmentId":"${ASSIGNMENT_ID}","runtimeAssignmentGeneration":1,"sandboxId":"sandbox-1","sandboxGeneration":1}}`,
    },
    {
      caseName: "duplicate nested runtimeAssignmentId",
      payloadJson: `{"type":"run.emergency-stop","sessionId":"${SESSION_ID}","agentRunId":"run-1","reason":"Unexpected production target","revokeAllRunGrants":true,"runtimeBinding":{"runtimeAssignmentId":"${ASSIGNMENT_ID}","runtimeAssignmentId":"${ASSIGNMENT_ID}","runtimeAssignmentGeneration":1,"sandboxId":"sandbox-1","sandboxGeneration":1}}`,
    },
  ] as const)(
    "rolls back emergency-cutover evidence for an accepted payload with $caseName",
    ({ caseName, payloadJson }) => {
      database = openTeamSessionDatabase({ filename });
      const db = database.db;
      const sourceKey = seedEmergencyCutoverEvidenceFixture(db);

      expect(() =>
        db
          .transaction(() => {
            insertEmergencyCutoverEvidence(db, sourceKey);
            db.prepare(
              `INSERT INTO accepted_commands
                 (source_scope, source_key, payload_digest, accepted_sequence, command_type,
                  actor_kind, actor_user_id, actor_display_name, payload_json, result_json,
                  secret_result, accepted_at_ms)
               VALUES ('vitest:runtime-command', ?, ?, 1, 'run.emergency-stop',
                       'human', 'user-alice', 'Alice', ?, '{}', 0, 100)`
            ).run(sourceKey, digestFor(`accepted:${caseName}`), payloadJson);
          })
          .immediate()
      ).toThrow(/Accepted command does not match Runtime outbox evidence/);
      expect(
        db
          .prepare(
            `SELECT COUNT(*) AS count FROM runtime_outbox_supersession_evidence
             WHERE target_outbox_id = 'malformed-emergency-target'`
          )
          .get()
      ).toEqual({ count: 0 });
      expect(
        db
          .prepare(
            `SELECT COUNT(*) AS count FROM accepted_commands
             WHERE source_scope = 'vitest:runtime-command' AND source_key = ?`
          )
          .get(sourceKey)
      ).toEqual({ count: 0 });
      expect(
        db
          .prepare(
            `SELECT id, status, attempts, lease_owner, lease_expires_at_ms
             FROM runtime_outbox
             WHERE id IN ('malformed-emergency-target', 'malformed-emergency-source')
             ORDER BY id`
          )
          .all()
      ).toEqual([
        {
          id: "malformed-emergency-source",
          status: "pending",
          attempts: 0,
          lease_owner: null,
          lease_expires_at_ms: null,
        },
        {
          id: "malformed-emergency-target",
          status: "pending",
          attempts: 0,
          lease_owner: null,
          lease_expires_at_ms: null,
        },
      ]);
    }
  );

  it("supersedes every later assignee-loss generation when a marked emergency retirement is reclaimed", async () => {
    database = openTeamSessionDatabase({ filename });
    seedRetiredBindingRetryFixture(database.db);
    database.close();
    database = undefined;

    let now = 200;
    let generated = 0;
    const teamSessions = createTeamSessions({
      filename,
      clock: () => now,
      idGenerator: () => {
        generated += 1;
        return `00000000-0000-4000-8000-${String(generated).padStart(12, "0")}`;
      },
    });
    try {
      const [firstClaim] = await teamSessions.claimRuntimeOutbox({
        workerId: "worker-1",
        limit: 1,
        leaseDurationMs: 1_000,
      });
      expect(firstClaim).toMatchObject({
        outboxId: "retired-binding-source",
        kind: "runtime.session.retire",
        attempts: 1,
      });
      if (!firstClaim) throw new Error("Expected the initial emergency-retire claim");
      await teamSessions.markRuntimeOutboxDispatch({
        outboxId: firstClaim.outboxId,
        workerId: "worker-1",
        expectedAttempt: firstClaim.attempts,
        expectedLeaseExpiresAtMs: firstClaim.leaseExpiresAtMs,
      });

      now = firstClaim.leaseExpiresAtMs + 1;
      const [reclaimed] = await teamSessions.claimRuntimeOutbox({
        workerId: "worker-1",
        limit: 1,
        leaseDurationMs: 1_000,
      });
      expect(reclaimed).toMatchObject({
        outboxId: "retired-binding-source",
        kind: "runtime.session.retire",
        attempts: 2,
      });
      if (!reclaimed) throw new Error("Expected the reclaimed emergency-retire delivery");
      const acknowledgement: SessionCommand = {
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        type: "runtime.outbox.acknowledge",
        outboxId: reclaimed.outboxId,
        workerId: "worker-1",
        expectedAttempt: reclaimed.attempts,
        expectedLeaseExpiresAtMs: reclaimed.leaseExpiresAtMs,
        actor: { kind: "system", userId: "worker-1", displayName: "Runtime Worker" },
        idempotency: { scope: "vitest:retired-binding", key: "ack-reclaimed-retire" },
        occurredAtMs: now,
      };
      await teamSessions.dispatch(acknowledgement);

      await expect(
        teamSessions.claimRuntimeOutbox({
          workerId: "worker-1",
          limit: 1,
          leaseDurationMs: 1_000,
        })
      ).resolves.toEqual([]);
    } finally {
      teamSessions.close();
    }

    const after = new Database(filename, { readonly: true });
    try {
      expect(
        after
          .prepare(
            `SELECT id, status, attempts, dispatch_interlock_attempt, delivered_at_ms
             FROM runtime_outbox ORDER BY session_sequence`
          )
          .all()
      ).toEqual([
        {
          id: "retired-binding-source",
          status: "delivered",
          attempts: 2,
          dispatch_interlock_attempt: 1,
          delivered_at_ms: now,
        },
        {
          id: "retired-binding-fence-generation-3",
          status: "superseded",
          attempts: 0,
          dispatch_interlock_attempt: null,
          delivered_at_ms: now,
        },
        {
          id: "retired-binding-fence-generation-4",
          status: "superseded",
          attempts: 0,
          dispatch_interlock_attempt: null,
          delivered_at_ms: now,
        },
      ]);
      expect(
        after
          .prepare(
            `SELECT target_outbox_id, source_attempts,
                    source_dispatch_interlock_attempt, reason
             FROM runtime_outbox_supersession_evidence
             ORDER BY target_outbox_id`
          )
          .all()
      ).toEqual([
        {
          target_outbox_id: "retired-binding-fence-generation-3",
          source_attempts: 2,
          source_dispatch_interlock_attempt: 1,
          reason: "retired-binding",
        },
        {
          target_outbox_id: "retired-binding-fence-generation-4",
          source_attempts: 2,
          source_dispatch_interlock_attempt: 1,
          reason: "retired-binding",
        },
      ]);
      expect(
        after
          .prepare(`SELECT status, retired_at_ms FROM runtime_assignments WHERE id = ?`)
          .get(ASSIGNMENT_ID)
      ).toEqual({ status: "retired", retired_at_ms: now });
      expect(
        after
          .prepare(
            `SELECT lifecycle, state_version, terminal_at_ms
             FROM agent_runs WHERE id = 'run-1'`
          )
          .get()
      ).toEqual({ lifecycle: "emergency-stopped", state_version: 3, terminal_at_ms: now });
    } finally {
      after.close();
    }
  });

  it("accepts v8 when a peer wins after this opener observes the committed v7 boundary", () => {
    createRuntimeAssignmentOutboxSchemaV7Fixture(filename);
    const pragmaDescriptor = Object.getOwnPropertyDescriptor(Database.prototype, "pragma");
    if (!pragmaDescriptor?.value) throw new Error("Expected better-sqlite3 pragma method");
    let versionReads = 0;
    let peerAdvanceStarted = false;
    let peerAdvanced = false;
    Object.defineProperty(Database.prototype, "pragma", {
      ...pragmaDescriptor,
      value(this: Database.Database, source: string, ...args: unknown[]) {
        const result = Reflect.apply(pragmaDescriptor.value, this, [source, ...args]);
        if (!peerAdvanceStarted && source === "user_version") {
          versionReads += 1;
          if (versionReads === 4) {
            peerAdvanceStarted = true;
            const peer = openTeamSessionDatabase({ filename });
            try {
              expect(peer.db.pragma("user_version", { simple: true })).toBe(8);
              peerAdvanced = true;
            } finally {
              peer.close();
            }
          }
        }
        return result;
      },
    });
    try {
      database = openTeamSessionDatabase({ filename });
    } finally {
      Object.defineProperty(Database.prototype, "pragma", pragmaDescriptor);
    }

    expect(peerAdvanceStarted).toBe(true);
    expect(peerAdvanced).toBe(true);
    expect(database.db.pragma("user_version", { simple: true })).toBe(8);
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
    expect(database.db.pragma("quick_check", { simple: true })).toBe("ok");
  });

  it("migrates genuine v5 through v6, v7, and v8 without fabricating observation trust", () => {
    createRuntimeReceiptFollowSchemaV5Fixture(filename);
    const before = new Database(filename, { readonly: true });
    try {
      expect(before.pragma("user_version", { simple: true })).toBe(5);
      expect(
        before
          .prepare(
            `SELECT COUNT(*) AS count FROM sqlite_schema
             WHERE type = 'table' AND name LIKE 'runtime_receipt_follow_%'`
          )
          .get()
      ).toEqual({ count: 0 });
    } finally {
      before.close();
    }

    database = openTeamSessionDatabase({ filename });
    expect(database.db.pragma("user_version", { simple: true })).toBe(8);
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_principal_observation_keys`).get()
    ).toEqual({ count: 0 });
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_receipt_follow_streams`).get()
    ).toEqual({ count: 0 });
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
  });

  it("backfills one verified unsigned incident from an exact v6 compensating receipt", () => {
    createRuntimeCompensationSchemaV6Fixture(filename);
    const legacy = new Database(filename);
    try {
      legacy.pragma("foreign_keys = ON");
      seedRuntimeRunCommand(legacy);
      claimRuntimeRunDispatch(legacy, "runtime-command-1");
      insertRuntimeRunReceipt(legacy);
      legacy
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'compensating', lease_owner = NULL, lease_expires_at_ms = NULL,
               updated_at_ms = 110
           WHERE command_id = 'runtime-command-1'`
        )
        .run();
    } finally {
      legacy.close();
    }

    database = openTeamSessionDatabase({ filename });
    expect(database.db.pragma("user_version", { simple: true })).toBe(8);
    expect(
      database.db
        .prepare(
          `SELECT trust_state, source_command_id, source_receipt_id,
                  source_enforced_fence, safety_fence,
                  source_effect_ref_commitment,
                  source_required_effect_enforcer_set_digest,
                  lifecycle_enforcement_subject_digest,
                  lifecycle_aggregate_proof_digest
           FROM runtime_compensation_incidents`
        )
        .get()
    ).toEqual({
      trust_state: "verified",
      source_command_id: "runtime-command-1",
      source_receipt_id: "receipt-1",
      source_enforced_fence: 2,
      safety_fence: 3,
      source_effect_ref_commitment: `effect:v1:${digestFor("runtime-command-1-effect")}`,
      source_required_effect_enforcer_set_digest: EFFECT_ENFORCER_SET_DIGEST,
      lifecycle_enforcement_subject_digest: ENFORCEMENT_SUBJECT_DIGEST,
      lifecycle_aggregate_proof_digest: AGGREGATE_PROOF_DIGEST,
    });
    expect(
      database.db
        .prepare(
          `SELECT allocated_fence FROM runtime_binding_safety_fences
           WHERE runtime_assignment_id = ?`
        )
        .get(ASSIGNMENT_ID)
    ).toEqual({ allocated_fence: 3 });
    for (const table of [
      "runtime_compensation_commands",
      "runtime_compensation_dispatch",
      "runtime_compensation_receipts",
      "runtime_compensation_effects",
      "runtime_compensation_follow_events",
    ]) {
      expect(database.db.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get()).toEqual({
        count: 0,
      });
    }
    expect(
      database.db
        .prepare(
          `SELECT status FROM runtime_run_command_dispatch
           WHERE command_id = 'runtime-command-1'`
        )
        .get()
    ).toEqual({ status: "compensating" });
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
    expect(database.db.pragma("quick_check", { simple: true })).toBe("ok");
  });

  it("backfills a v5 compensating receipt as a non-dispatchable legacy incident", () => {
    createRuntimeReceiptFollowSchemaV5Fixture(filename);
    const legacy = new Database(filename);
    try {
      legacy.pragma("foreign_keys = ON");
      seedRuntimeRunCommand(legacy);
      claimRuntimeRunDispatch(legacy, "runtime-command-1");
      insertRuntimeRunReceipt(legacy);
      legacy
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'compensating', lease_owner = NULL, lease_expires_at_ms = NULL,
               updated_at_ms = 110
           WHERE command_id = 'runtime-command-1'`
        )
        .run();
    } finally {
      legacy.close();
    }

    database = openTeamSessionDatabase({ filename });
    expect(
      database.db
        .prepare(
          `SELECT trust_state, source_enforced_fence, safety_fence,
                  source_effect_ref_commitment,
                  source_required_effect_enforcer_set_digest,
                  lifecycle_enforcement_subject_digest,
                  lifecycle_aggregate_proof_digest, source_proof_verified_at_ms
           FROM runtime_compensation_incidents`
        )
        .get()
    ).toEqual({
      trust_state: "legacy-untrusted",
      source_enforced_fence: 2,
      safety_fence: 3,
      source_effect_ref_commitment: null,
      source_required_effect_enforcer_set_digest: null,
      lifecycle_enforcement_subject_digest: null,
      lifecycle_aggregate_proof_digest: null,
      source_proof_verified_at_ms: null,
    });
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_commands`).get()
    ).toEqual({ count: 0 });
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
  });

  it("rolls back v7 when a compensating v6 dispatch has lost its source receipt", () => {
    createRuntimeCompensationSchemaV6Fixture(filename);
    const legacy = new Database(filename);
    try {
      legacy.pragma("foreign_keys = ON");
      seedRuntimeRunCommand(legacy);
      claimRuntimeRunDispatch(legacy, "runtime-command-1");
      insertRuntimeRunReceipt(legacy);
      legacy
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'compensating', lease_owner = NULL, lease_expires_at_ms = NULL,
               updated_at_ms = 110
           WHERE command_id = 'runtime-command-1'`
        )
        .run();
      legacy.exec(`DROP TRIGGER runtime_run_command_receipts_immutable_delete`);
      legacy.prepare(`DELETE FROM runtime_run_command_receipts WHERE id = 'receipt-1'`).run();
    } finally {
      legacy.close();
    }

    expect(() => openTeamSessionDatabase({ filename })).toThrow(
      /compensating dispatch without evidence/
    );
    const after = new Database(filename, { readonly: true });
    try {
      expect(after.pragma("user_version", { simple: true })).toBe(6);
      expect(
        after
          .prepare(
            `SELECT COUNT(*) AS count FROM sqlite_schema
             WHERE type = 'table' AND name LIKE 'runtime_compensation_%'`
          )
          .get()
      ).toEqual({ count: 0 });
    } finally {
      after.close();
    }
  });

  it("rolls back v7 instead of compensating a legacy lifecycle effect that was already applied", () => {
    createRuntimeCompensationSchemaV6Fixture(filename);
    const legacy = new Database(filename);
    try {
      legacy.pragma("foreign_keys = ON");
      seedRuntimeRunCommand(legacy);
      claimRuntimeRunDispatch(legacy, "runtime-command-1");
      insertRuntimeRunReceipt(legacy);
      insertRuntimeRequestEvent(legacy, 2, "event:pause-enforced", { type: "run.paused" });
      insertRuntimeRunEffect(legacy);
      legacy
        .prepare(
          `UPDATE agent_runs
           SET lifecycle = 'paused', state_version = 2, updated_at_ms = 115
           WHERE id = 'run-1'`
        )
        .run();
      legacy
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'compensating', lease_owner = NULL, lease_expires_at_ms = NULL,
               updated_at_ms = 116
           WHERE command_id = 'runtime-command-1'`
        )
        .run();
    } finally {
      legacy.close();
    }

    expect(() => openTeamSessionDatabase({ filename })).toThrow(
      /compensating dispatch with an applied lifecycle effect/
    );
    const after = new Database(filename, { readonly: true });
    try {
      expect(after.pragma("user_version", { simple: true })).toBe(6);
      expect(
        after
          .prepare(
            `SELECT COUNT(*) AS count FROM sqlite_schema
             WHERE type = 'table' AND name LIKE 'runtime_compensation_%'`
          )
          .get()
      ).toEqual({ count: 0 });
      expect(
        after
          .prepare(
            `SELECT COUNT(*) AS count FROM runtime_run_command_effects
             WHERE command_id = 'runtime-command-1'`
          )
          .get()
      ).toEqual({ count: 1 });
    } finally {
      after.close();
    }
  });

  it.each([false, true])(
    "parks a genuine v5 processing dispatch without redispatch (accepted receipt: %s)",
    async (withAcceptedReceipt) => {
      createRuntimeReceiptFollowSchemaV5Fixture(filename);
      const legacy = new Database(filename);
      try {
        legacy.pragma("foreign_keys = ON");
        seedRuntimeRunCommand(legacy);
        claimRuntimeRunDispatch(legacy, "runtime-command-1");
        if (withAcceptedReceipt) {
          insertRuntimeRunReceipt(legacy, {
            outcome: "accepted",
            receiptDigest: digestFor("legacy-accepted-receipt"),
          });
        }
        expect(
          legacy
            .prepare(
              `SELECT status, attempts, available_at_ms, lease_owner,
                      lease_expires_at_ms, updated_at_ms
               FROM runtime_run_command_dispatch WHERE command_id = 'runtime-command-1'`
            )
            .get()
        ).toEqual({
          status: "processing",
          attempts: 1,
          available_at_ms: 100,
          lease_owner: "worker-1",
          lease_expires_at_ms: 200,
          updated_at_ms: 101,
        });
      } finally {
        legacy.close();
      }

      database = openTeamSessionDatabase({ filename });
      const lifecycle = createSqliteRuntimeLifecycleJournal({
        db: database.db,
        idGenerator: () => "migration-runtime-journal-event",
      });
      const expectedDispatch = {
        status: "awaiting-receipt",
        attempts: 1,
        available_at_ms: 101,
        lease_owner: null,
        lease_expires_at_ms: null,
        dispatch_interlock_acquired_at_ms: null,
        last_safe_error_code: "migration_dispatch_uncertain",
        updated_at_ms: 101,
      };
      const readDispatch = () =>
        database!.db
          .prepare(
            `SELECT status, attempts, available_at_ms, lease_owner, lease_expires_at_ms,
                    dispatch_interlock_acquired_at_ms, last_safe_error_code, updated_at_ms
             FROM runtime_run_command_dispatch WHERE command_id = 'runtime-command-1'`
          )
          .get();

      expect(readDispatch()).toEqual(expectedDispatch);
      expect(
        database.db
          .prepare(
            `SELECT COUNT(*) AS count FROM runtime_run_command_receipts
             WHERE command_id = 'runtime-command-1'`
          )
          .get()
      ).toEqual({ count: withAcceptedReceipt ? 1 : 0 });

      await lifecycle.reconcile({ nowMs: 250 });
      await expect(
        lifecycle.claim({
          workerId: "replacement-worker",
          limit: 1,
          leaseDurationMs: 30_000,
          nowMs: 250,
        })
      ).resolves.toEqual([]);
      expect(readDispatch()).toEqual(expectedDispatch);
      expect(database.db.pragma("foreign_key_check")).toEqual([]);
    }
  );

  it("fences receipt-follow keys, leases, and cursor advancement to exact durable evidence", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${"A".repeat(100)}\n-----END PUBLIC KEY-----`;
    database.db
      .prepare(
        `INSERT INTO runtime_principal_observation_keys
           (runtime_assignment_id, session_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id,
            runtime_authorization_generation, issuer_key_id,
            public_key_spki_pem, public_key_spki_digest, created_at_ms)
         VALUES (?, ?, 1, 'sandbox-1', 1, 'principal-1', 1,
                 'observer-key:v1', ?, ?, 2)`
      )
      .run(ASSIGNMENT_ID, SESSION_ID, publicKeyPem, digestFor("observer-key:v1"));
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_principal_observation_keys
           SET issuer_key_id = 'attacker-key' WHERE runtime_assignment_id = ?`
        )
        .run(ASSIGNMENT_ID)
    ).toThrow(/observation keys are immutable/);

    database.db
      .prepare(
        `INSERT INTO runtime_receipt_follow_streams
           (runtime_assignment_id, session_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id,
            runtime_authorization_generation, issuer_key_id, public_key_spki_digest,
            status, attempts, lease_version, available_at_ms, lease_owner,
            lease_expires_at_ms, cursor, last_observation_digest, receipt_sequence,
            last_safe_error_code, created_at_ms, updated_at_ms)
         VALUES (?, ?, 1, 'sandbox-1', 1, 'principal-1', 1,
                 'observer-key:v1', ?, 'pending', 0, 0, 2, NULL, NULL,
                 NULL, NULL, 0, NULL, 2, 2)`
      )
      .run(ASSIGNMENT_ID, SESSION_ID, digestFor("observer-key:v1"));
    database.db
      .prepare(
        `UPDATE runtime_receipt_follow_streams
         SET status = 'processing', attempts = 1, lease_version = 1,
             lease_owner = 'follow-worker-1', lease_expires_at_ms = 1_000,
             updated_at_ms = 10
         WHERE runtime_assignment_id = ? AND runtime_authorization_generation = 1`
      )
      .run(ASSIGNMENT_ID);

    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_receipt_follow_streams
           SET status = 'pending', available_at_ms = 20,
               lease_owner = NULL, lease_expires_at_ms = NULL,
               cursor = 'forged-cursor', last_observation_digest = ?,
               receipt_sequence = 1, updated_at_ms = 20
           WHERE runtime_assignment_id = ? AND runtime_authorization_generation = 1`
        )
        .run(digestFor("forged-observation"), ASSIGNMENT_ID)
    ).toThrow(/Invalid Runtime receipt follow stream transition/);
    expect(
      database.db
        .prepare(
          `SELECT status, attempts, lease_version, cursor, receipt_sequence
           FROM runtime_receipt_follow_streams WHERE runtime_assignment_id = ?`
        )
        .get(ASSIGNMENT_ID)
    ).toEqual({
      status: "processing",
      attempts: 1,
      lease_version: 1,
      cursor: null,
      receipt_sequence: 0,
    });
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
    ).toThrow(/FOREIGN KEY constraint failed|Run policy effect-enforcer set does not match/);
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

    expect(database.db.pragma("user_version", { simple: true })).toBe(8);
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
    expect(migratedOutbox).toEqual({
      ...beforeMigration.outbox,
      dispatch_interlock_attempt: 3,
      dispatch_interlock_acquired_at_ms: 100,
    });
    expect(migratedOutbox).toMatchObject({
      payload_json: JSON.stringify({
        sessionId: SESSION_ID,
        runtimeKind: "local-tmux",
        tmuxName: "phase-four-schema",
        runtimeAuthorizationGeneration: 1,
      }),
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

  it("migrates a populated v4 Runtime journal through v5, v6, v7, and v8 without losing truth", () => {
    const beforeMigration = createPopulatedRuntimeRunSchemaV4Fixture(filename);

    database = openTeamSessionDatabase({ filename });

    expect(database.db.pragma("user_version", { simple: true })).toBe(8);
    expect(
      database.db
        .prepare(`SELECT * FROM runtime_run_commands WHERE id = ?`)
        .get("runtime-command-1")
    ).toEqual({ ...beforeMigration.command, required_effect_enforcer_set_digest: null });
    expect(
      database.db
        .prepare(`SELECT * FROM runtime_run_command_receipts WHERE id = ?`)
        .get("receipt-1")
    ).toEqual({
      ...beforeMigration.receipt,
      required_effect_enforcer_set_digest: null,
      enforcement_subject_digest: null,
      aggregate_proof_digest: null,
      proof_verified_at_ms: null,
    });
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

      expect(database.db.pragma("user_version", { simple: true })).toBe(8);
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

  it("keeps pre-dispatch emergency quarantine reachable and rejects a late start effect", () => {
    database = openTeamSessionDatabase({ filename });
    seedStartingRuntimeRunCommand(database.db);
    claimRuntimeRunDispatch(database.db, "runtime-command-start", 101, "worker-1", false);

    database.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = 'pausing', state_version = 2, updated_at_ms = 105
         WHERE id = 'run-1'`
      )
      .run();
    expect(() =>
      insertRuntimeRunReceipt(database!.db, { commandId: "runtime-command-start" })
    ).toThrow(/dispatch is not accepting receipts/);
    insertRuntimeRequestEvent(database.db, 2, "event:late-start-enforced", {
      commandId: "runtime-command-start",
      type: "run.started",
      operation: "run.start",
    });
    expect(() =>
      insertRuntimeRunEffect(database!.db, digestFor("late-start-effect"), {
        commandId: "runtime-command-start",
      })
    ).toThrow(/does not match current dispatch and Run state|requires a verified enforced receipt/);
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

    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'awaiting-receipt', available_at_ms = 110,
             lease_owner = NULL, lease_expires_at_ms = NULL, updated_at_ms = 110
         WHERE command_id = 'runtime-command-1'`
      )
      .run();
    database.db
      .prepare(
        `UPDATE agent_runs
         SET lifecycle = 'pausing', state_version = 2, updated_at_ms = 105
         WHERE id = 'run-1'`
      )
      .run();
    insertRuntimeRunReceipt(database.db);
    insertRuntimeCompensationIncident(database.db);
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

  it("serializes exact-binding safety allocation above durable high-water", () => {
    database = openTeamSessionDatabase({ filename });
    seedSessionAndAssignment(database.db);

    const compareAndAdvance = database.db.prepare(
      `UPDATE runtime_binding_safety_fences
       SET allocated_fence = allocated_fence + 1, updated_at_ms = 10
       WHERE runtime_assignment_id = ? AND allocated_fence = ?
       RETURNING allocated_fence`
    );
    expect(compareAndAdvance.get(ASSIGNMENT_ID, 1)).toEqual({ allocated_fence: 2 });
    expect(compareAndAdvance.get(ASSIGNMENT_ID, 1)).toBeUndefined();
    database.db.prepare(`UPDATE sessions SET steering_revision = 7 WHERE id = ?`).run(SESSION_ID);
    expect(
      database.db
        .prepare(
          `UPDATE runtime_binding_safety_fences
           SET allocated_fence = MAX(
                 allocated_fence,
                 (SELECT steering_revision FROM sessions WHERE id = ?)
               ) + 1,
               updated_at_ms = 11
           WHERE runtime_assignment_id = ?
           RETURNING allocated_fence`
        )
        .get(SESSION_ID, ASSIGNMENT_ID)
    ).toEqual({ allocated_fence: 8 });
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_binding_safety_fences
           SET allocated_fence = 9007199254740992, updated_at_ms = 11
           WHERE runtime_assignment_id = ?`
        )
        .run(ASSIGNMENT_ID)
    ).toThrow(/beyond durable high-water|CHECK constraint failed/);
    expect(() =>
      database!.db
        .prepare(
          `INSERT INTO runtime_binding_safety_fences
             (team_id, project_id, session_id, runtime_assignment_id,
              runtime_assignment_generation, sandbox_id, sandbox_generation,
              runtime_principal_id, allocated_fence, updated_at_ms)
           SELECT team_id, project_id, session_id, id, generation, sandbox_id,
                  sandbox_generation, runtime_principal_id, 8, 11
           FROM runtime_assignments WHERE id = ?`
        )
        .run(ASSIGNMENT_ID)
    ).toThrow(/UNIQUE constraint failed/);
  });

  it("requires an exact proof-backed compensation effect before quarantining the source", () => {
    database = openTeamSessionDatabase({ filename });
    seedRuntimeRunCommand(database.db);
    claimRuntimeRunDispatch(database.db, "runtime-command-1");
    insertRuntimeRunReceipt(database.db);
    insertRuntimeCompensationIncident(database.db);
    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'compensating', lease_owner = NULL, lease_expires_at_ms = NULL,
             updated_at_ms = 110
         WHERE command_id = 'runtime-command-1'`
      )
      .run();
    insertRuntimeCompensationCommand(database.db);

    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'quarantined', last_safe_error_code = 'stale_enforced_effect_compensated',
               terminal_at_ms = 130, updated_at_ms = 130
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime Run command dispatch transition|lacks durable evidence/);

    database.db
      .prepare(
        `UPDATE runtime_compensation_dispatch
         SET status = 'processing', attempts = 1, lease_owner = 'security-worker-1',
             lease_expires_at_ms = 220, updated_at_ms = 121
         WHERE compensation_command_id = 'compensation-command-1'`
      )
      .run();
    database.db
      .prepare(
        `UPDATE runtime_compensation_dispatch
         SET dispatch_interlock_acquired_at_ms = 122, updated_at_ms = 122
         WHERE compensation_command_id = 'compensation-command-1'`
      )
      .run();
    insertRuntimeCompensationReceiptAndEffect(database.db);
    database.db
      .prepare(
        `UPDATE runtime_compensation_dispatch
         SET status = 'enforced', lease_owner = NULL, lease_expires_at_ms = NULL,
             terminal_at_ms = 150, updated_at_ms = 150
         WHERE compensation_command_id = 'compensation-command-1'`
      )
      .run();
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_run_command_dispatch
           SET status = 'quarantined', last_safe_error_code = 'stale_enforced_effect_compensated',
               terminal_at_ms = 151, updated_at_ms = 151
           WHERE command_id = 'runtime-command-1'`
        )
        .run()
    ).not.toThrow();
    expect(
      database.db
        .prepare(
          `SELECT status FROM runtime_run_command_dispatch
           WHERE command_id = 'runtime-command-1'`
        )
        .get()
    ).toEqual({ status: "quarantined" });
    expect(database.db.pragma("foreign_key_check")).toEqual([]);
  });

  it("fails closed when compensation dispatch transitions omit their required safe error", () => {
    database = openTeamSessionDatabase({ filename });
    seedPendingRuntimeCompensationCommand(database.db);

    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_compensation_dispatch
           SET status = 'expired-before-dispatch', last_safe_error_code = NULL,
               terminal_at_ms = 121, updated_at_ms = 121
           WHERE compensation_command_id = 'compensation-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime compensation dispatch transition/);
    expect(runtimeCompensationDispatchState(database.db)).toMatchObject({
      status: "pending",
      attempts: 0,
      last_safe_error_code: null,
    });

    database.db
      .prepare(
        `UPDATE runtime_compensation_dispatch
         SET status = 'processing', attempts = 1, lease_owner = 'security-worker-1',
             lease_expires_at_ms = 220, updated_at_ms = 121
         WHERE compensation_command_id = 'compensation-command-1'`
      )
      .run();
    expect(() =>
      database!.db
        .prepare(
          `UPDATE runtime_compensation_dispatch
           SET status = 'pending', available_at_ms = 122,
               lease_owner = NULL, lease_expires_at_ms = NULL,
               last_safe_error_code = NULL, updated_at_ms = 122
           WHERE compensation_command_id = 'compensation-command-1'`
        )
        .run()
    ).toThrow(/Invalid Runtime compensation dispatch transition/);
    expect(runtimeCompensationDispatchState(database.db)).toMatchObject({
      status: "processing",
      attempts: 1,
      lease_owner: "security-worker-1",
      last_safe_error_code: null,
    });
  });

  it("rejects duplicate compensation receipts whose inner identity is not exact-bound", () => {
    database = openTeamSessionDatabase({ filename });
    seedPendingRuntimeCompensationCommand(database.db);
    interlockRuntimeCompensationDispatch(database.db);
    const validReceiptJson = runtimeCompensationDuplicateReceiptJson(database.db);
    const mutations: ReadonlyArray<readonly [path: string, value: string | number]> = [
      ["$.originalReceipt.receiptKind", "runtime.lifecycle"],
      ["$.originalReceipt.compensationId", "other-compensation"],
      ["$.originalReceipt.commandId", "other-command"],
      ["$.originalReceipt.outcome", "accepted"],
      ["$.originalReceipt.observedRuntimeAuthorizationGeneration", 2],
      ["$.originalReceipt.binding.teamId", "other-team"],
      ["$.originalReceipt.binding.projectId", "other-project"],
      ["$.originalReceipt.binding.sessionId", "other-session"],
      ["$.originalReceipt.binding.runtimeAssignmentId", "other-assignment"],
      ["$.originalReceipt.binding.runtimeAssignmentGeneration", 2],
      ["$.originalReceipt.binding.sandboxId", "other-sandbox"],
      ["$.originalReceipt.binding.sandboxGeneration", 2],
      ["$.originalReceipt.binding.runtimePrincipalId", "other-principal"],
      ["$.originalReceiptDigest", digestFor("other-original-receipt")],
    ];

    for (const [path, value] of mutations) {
      const tampered = database.db
        .prepare(`SELECT json_set(?, ?, ?) AS receipt_json`)
        .get(validReceiptJson, path, value) as { receipt_json: string };
      expect(() =>
        insertRuntimeCompensationDuplicateReceipt(database!.db, tampered.receipt_json)
      ).toThrow(/CHECK constraint failed/);
      expect(
        database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_receipts`).get()
      ).toEqual({ count: 0 });
    }

    expect(() =>
      insertRuntimeCompensationDuplicateReceipt(database!.db, validReceiptJson)
    ).not.toThrow();
  });

  it("rolls back a compensation effect whose enforced fence outruns its allocator", () => {
    database = openTeamSessionDatabase({ filename });
    seedPendingRuntimeCompensationCommand(database.db);
    interlockRuntimeCompensationDispatch(database.db);
    const command = database.db
      .prepare(`SELECT safety_fence FROM runtime_compensation_commands WHERE id = ?`)
      .get("compensation-command-1") as { safety_fence: number };

    expect(() =>
      insertRuntimeCompensationReceiptAndEffect(database!.db, { advanceSafetyFence: false })
    ).toThrow(/Runtime compensation effect requires exact verified containment/);
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_receipts`).get()
    ).toEqual({ count: 0 });
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_effects`).get()
    ).toEqual({ count: 0 });
    expect(
      database.db
        .prepare(
          `SELECT COUNT(*) AS count FROM session_events
           WHERE type = 'run.runtime-command.compensated'`
        )
        .get()
    ).toEqual({ count: 0 });
    expect(
      database.db
        .prepare(
          `SELECT allocated_fence FROM runtime_binding_safety_fences
           WHERE runtime_assignment_id = ?`
        )
        .get(ASSIGNMENT_ID)
    ).toEqual({ allocated_fence: command.safety_fence });

    expect(() => insertRuntimeCompensationReceiptAndEffect(database!.db)).not.toThrow();
    expect(
      database.db
        .prepare(
          `SELECT allocated_fence FROM runtime_binding_safety_fences
           WHERE runtime_assignment_id = ?`
        )
        .get(ASSIGNMENT_ID)
    ).toEqual({ allocated_fence: command.safety_fence + 1 });
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
      /FOREIGN KEY constraint failed|JSON scope does not match|does not match current Run state|Runtime command effect-enforcer set does not match/
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
    ).toThrow(
      /CHECK constraint failed|JSON scope does not match|source event does not match|Runtime command effect-enforcer set does not match/
    );
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

    claimRuntimeRunDispatch(database.db, "runtime-command-1");
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
    ).toThrow(
      /CHECK constraint failed|JSON scope does not match|Runtime enforced receipt lacks an exact verified aggregate proof|Runtime enforced receipt fence is not a safe integer/
    );
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
      ).toThrow(
        /CHECK constraint failed|Runtime enforced receipt lacks an exact verified aggregate proof/
      );
    }
  );

  it.each(["rejected", "quarantined"] as const)(
    "terminalizes %s from a complete version-one duplicate receipt",
    (outcome) => {
      database = openTeamSessionDatabase({ filename });
      seedRuntimeRunCommand(database.db);
      claimRuntimeRunDispatch(database.db, "runtime-command-1");
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
    claimRuntimeRunDispatch(database.db, "runtime-command-1");
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
    claimRuntimeRunDispatch(database.db, "runtime-command-1");
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
  const hasEnforcerSet = hasColumn(
    db,
    "run_policy_revisions",
    "required_effect_enforcer_set_digest"
  );
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
          runtime_authorization_generation${
            hasEnforcerSet ? ", required_effect_enforcer_set_digest" : ""
          }, yolo_confirmation_ref, created_at_ms)
       VALUES
         ('run-1', ?, 1, NULL, ?, ?, 'autonomous', 'continue-until-all-goals-achieved',
          'scoped-policy-1', '[]', ?, 'goal-set-1', 1,
          'ceiling-1', ?, ?, 1, 'sandbox-1', 1, 'principal-1', 1${
            hasEnforcerSet ? ", ?" : ""
          }, NULL, 20)`
    ).run(
      SESSION_ID,
      digestFor("policy-snapshot:run-1:1"),
      digestFor("policy-body:run-1:1"),
      JSON.stringify(completeLimits()),
      digestFor("project-ceiling"),
      ASSIGNMENT_ID,
      ...(hasEnforcerSet ? [EFFECT_ENFORCER_SET_DIGEST] : [])
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
  worker = "worker-1",
  acquireInterlock = true
): void {
  db.prepare(
    `UPDATE runtime_run_command_dispatch
     SET status = 'processing', attempts = attempts + 1, lease_owner = ?,
         lease_expires_at_ms = 200, updated_at_ms = ?
     WHERE command_id = ?`
  ).run(worker, now, commandId);
  if (
    acquireInterlock &&
    hasColumn(db, "runtime_run_command_dispatch", "dispatch_interlock_acquired_at_ms")
  ) {
    db.prepare(
      `UPDATE runtime_run_command_dispatch
       SET dispatch_interlock_acquired_at_ms = updated_at_ms
       WHERE command_id = ?`
    ).run(commandId);
  }
}

function insertRuntimeRequestEvent(
  db: Database.Database,
  sequence: number,
  eventId: string,
  options: {
    commandId?: string;
    type?: string;
    payload?: Record<string, unknown>;
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
  const payload =
    options.payload ??
    ({
      commandId,
      agentRunId: "run-1",
      operation,
      fromRunStateVersion,
      toRunStateVersion,
      targetLifecycle,
    } satisfies Record<string, unknown>);
  db.prepare(
    `INSERT INTO session_events
       (session_id, sequence, event_id, type, occurred_at_ms,
        actor_kind, actor_user_id, actor_display_name,
        source_scope, source_key, payload_json)
     VALUES (?, ?, ?, ?, 100,
             'human', 'user-alice', 'Alice', 'vitest:runtime-command', ?, ?)`
  ).run(SESSION_ID, sequence, eventId, eventType, eventId, JSON.stringify(payload));
}

function insertAcceptedRuntimeOutboxCommand(
  db: Database.Database,
  options: {
    acceptedSequence: number;
    sourceKey: string;
    commandType: "runtime.outbox.acknowledge" | "runtime.outbox.fail";
    workerId: string;
    outboxId: string;
    attempt: number;
    leaseExpiresAtMs: number;
    retryable?: boolean;
    errorCode?: string;
  }
): void {
  const payload = {
    type: options.commandType,
    outboxId: options.outboxId,
    workerId: options.workerId,
    expectedAttempt: options.attempt,
    expectedLeaseExpiresAtMs: options.leaseExpiresAtMs,
    ...(options.commandType === "runtime.outbox.fail"
      ? { retryable: options.retryable, errorCode: options.errorCode }
      : {}),
  };
  db.prepare(
    `INSERT INTO accepted_commands
       (source_scope, source_key, payload_digest, accepted_sequence, command_type,
        actor_kind, actor_user_id, actor_display_name, payload_json, result_json,
        secret_result, accepted_at_ms)
     VALUES ('vitest:evidence', ?, ?, ?, ?,
             'system', ?, 'Runtime Worker', ?, '{}', 0, 200)`
  ).run(
    options.sourceKey,
    digestFor(`accepted:${options.sourceKey}`),
    options.acceptedSequence,
    options.commandType,
    options.workerId,
    JSON.stringify(payload)
  );
}

function seedRuntimeOutboxAcknowledgementEvidenceFixture(db: Database.Database): void {
  seedSessionAndAssignment(db, { runtimeAuthorizationState: "pending" });
  insertRuntimeRequestEvent(db, 1, "event:malformed-ack-outbox", {
    type: "session.started",
    payload: {
      sessionId: SESSION_ID,
      runtimeKind: "local-tmux",
      runtimeAuthorizationGeneration: 1,
    },
  });
  db.prepare(
    `INSERT INTO runtime_outbox
       (id, session_id, session_sequence, kind, payload_json,
        status, attempts, created_at_ms)
     VALUES ('malformed-ack-outbox', ?, 1, 'runtime.session.ensure', ?,
             'pending', 0, 100)`
  ).run(
    SESSION_ID,
    JSON.stringify({
      sessionId: SESSION_ID,
      runtimeKind: "local-tmux",
      tmuxName: "phase-four-schema",
      runtimeAuthorizationGeneration: 1,
    })
  );
  db.prepare(
    `UPDATE runtime_outbox
     SET status = 'processing', attempts = 1,
         lease_owner = 'worker-1', lease_expires_at_ms = 500
     WHERE id = 'malformed-ack-outbox'`
  ).run();
  db.prepare(
    `UPDATE runtime_outbox
     SET dispatch_interlock_attempt = 1, dispatch_interlock_acquired_at_ms = 101
     WHERE id = 'malformed-ack-outbox'`
  ).run();
}

function seedEmergencyCutoverEvidenceFixture(db: Database.Database): string {
  seedSessionAndAssignment(db, { runtimeAuthorizationState: "pending" });
  insertRuntimeRequestEvent(db, 1, "event:malformed-emergency-target", {
    type: "session.started",
    payload: {
      sessionId: SESSION_ID,
      runtimeKind: "local-tmux",
      runtimeAuthorizationGeneration: 1,
    },
  });
  db.prepare(
    `INSERT INTO runtime_outbox
       (id, session_id, session_sequence, kind, payload_json,
        status, attempts, created_at_ms)
     VALUES ('malformed-emergency-target', ?, 1, 'runtime.session.ensure', ?,
             'pending', 0, 100)`
  ).run(
    SESSION_ID,
    JSON.stringify({
      sessionId: SESSION_ID,
      runtimeKind: "local-tmux",
      tmuxName: "phase-four-schema",
      runtimeAuthorizationGeneration: 1,
    })
  );
  insertRun(db, "run-1", "active");
  if (hasColumn(db, "runtime_authorization_epochs", "effect_enforcer_set_digest")) {
    db.prepare(
      `INSERT INTO runtime_authorization_epochs
         (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms,
          effect_enforcer_set_digest)
       VALUES (?, 2, ?, 1, 'sandbox-1', 1, 'principal-1', 200, ?)`
    ).run(SESSION_ID, ASSIGNMENT_ID, EFFECT_ENFORCER_SET_DIGEST);
  } else {
    db.prepare(
      `INSERT INTO runtime_authorization_epochs
         (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms)
       VALUES (?, 2, ?, 1, 'sandbox-1', 1, 'principal-1', 200)`
    ).run(SESSION_ID, ASSIGNMENT_ID);
  }
  db.prepare(
    `UPDATE sessions
     SET runtime_authorization_generation = 2, runtime_authorization_state = 'quarantined'
     WHERE id = ?`
  ).run(SESSION_ID);
  db.prepare(
    `UPDATE runtime_assignments
     SET runtime_authorization_generation = 2, status = 'quarantined'
     WHERE id = ?`
  ).run(ASSIGNMENT_ID);
  db.prepare(
    `UPDATE agent_runs
     SET lifecycle = 'pausing', state_version = 2,
         runtime_authorization_generation = 2, updated_at_ms = 200
     WHERE id = 'run-1'`
  ).run();
  const sourceKey = "event:malformed-emergency-source";
  insertRuntimeRequestEvent(db, 2, sourceKey, {
    type: "run.emergency-stop.requested",
    payload: {
      agentRunId: "run-1",
      runtimeAuthorizationGeneration: 2,
      reason: "Unexpected production target",
      revokeAllRunGrants: true,
    },
  });
  db.prepare(
    `INSERT INTO runtime_outbox
       (id, session_id, session_sequence, kind, payload_json,
        status, attempts, created_at_ms)
     VALUES ('malformed-emergency-source', ?, 2, 'runtime.session.retire', ?,
             'pending', 0, 100)`
  ).run(
    SESSION_ID,
    JSON.stringify({
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: 2,
      reason: "emergency-stop",
      agentRunId: "run-1",
      runtimeAssignmentId: ASSIGNMENT_ID,
      runtimeAssignmentGeneration: 1,
      sandboxId: "sandbox-1",
      sandboxGeneration: 1,
    })
  );
  return sourceKey;
}

function insertEmergencyCutoverEvidence(db: Database.Database, sourceKey: string): void {
  db.prepare(
    `INSERT INTO runtime_outbox_supersession_evidence
       (target_outbox_id, source_outbox_id, reason,
        target_status, target_attempts, target_lease_owner,
        target_lease_expires_at_ms, target_dispatch_interlock_attempt,
        target_dispatch_interlock_acquired_at_ms,
        source_attempts, source_lease_owner, source_lease_expires_at_ms,
        source_dispatch_interlock_attempt, source_dispatch_interlock_acquired_at_ms,
        command_source_scope, command_source_key, recorded_at_ms)
     VALUES ('malformed-emergency-target', 'malformed-emergency-source',
             'emergency-cutover', 'pending', 0, NULL, NULL, NULL, NULL,
             0, NULL, NULL, NULL, NULL, 'vitest:runtime-command', ?, 100)`
  ).run(sourceKey);
}

function seedRetiredBindingRetryFixture(db: Database.Database): void {
  seedSessionAndAssignment(db, { runtimeAuthorizationState: "pending" });
  insertRun(db, "run-1", "active");
  for (const generation of [2, 3, 4]) {
    if (hasColumn(db, "runtime_authorization_epochs", "effect_enforcer_set_digest")) {
      db.prepare(
        `INSERT INTO runtime_authorization_epochs
           (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms,
            effect_enforcer_set_digest)
         VALUES (?, ?, ?, 1, 'sandbox-1', 1, 'principal-1', 100, ?)`
      ).run(SESSION_ID, generation, ASSIGNMENT_ID, EFFECT_ENFORCER_SET_DIGEST);
    } else {
      db.prepare(
        `INSERT INTO runtime_authorization_epochs
           (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms)
         VALUES (?, ?, ?, 1, 'sandbox-1', 1, 'principal-1', 100)`
      ).run(SESSION_ID, generation, ASSIGNMENT_ID);
    }
  }
  db.prepare(
    `UPDATE sessions
     SET runtime_authorization_generation = 2, runtime_authorization_state = 'quarantined'
     WHERE id = ?`
  ).run(SESSION_ID);
  db.prepare(
    `UPDATE runtime_assignments
     SET runtime_authorization_generation = 2, status = 'quarantined'
     WHERE id = ?`
  ).run(ASSIGNMENT_ID);
  db.prepare(
    `UPDATE agent_runs
     SET lifecycle = 'pausing', state_version = 2,
         runtime_authorization_generation = 2, updated_at_ms = 100
     WHERE id = 'run-1'`
  ).run();
  insertRuntimeRequestEvent(db, 1, "event:retired-binding-source", {
    type: "run.emergency-stop.requested",
    payload: {
      agentRunId: "run-1",
      runtimeAuthorizationGeneration: 2,
      reason: "Unexpected production target",
      revokeAllRunGrants: true,
    },
  });
  db.prepare(
    `INSERT INTO runtime_outbox
       (id, session_id, session_sequence, kind, payload_json,
        status, attempts, created_at_ms)
     VALUES ('retired-binding-source', ?, 1, 'runtime.session.retire', ?,
             'pending', 0, 100)`
  ).run(
    SESSION_ID,
    JSON.stringify({
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: 2,
      reason: "emergency-stop",
      agentRunId: "run-1",
      runtimeAssignmentId: ASSIGNMENT_ID,
      runtimeAssignmentGeneration: 1,
      sandboxId: "sandbox-1",
      sandboxGeneration: 1,
    })
  );

  for (const [sequence, generation] of [
    [2, 3],
    [3, 4],
  ] as const) {
    db.prepare(
      `UPDATE sessions
       SET runtime_authorization_generation = ?, runtime_authorization_state = 'quarantined'
       WHERE id = ?`
    ).run(generation, SESSION_ID);
    insertRuntimeRequestEvent(
      db,
      sequence,
      `event:retired-binding-fence-generation-${generation}`,
      {
        type: "session.runtime-authorization.advanced",
        payload: {
          reason: "assignee-loss",
          runtimeAuthorizationGeneration: generation,
          enforcementState: "quarantined",
        },
      }
    );
    db.prepare(
      `INSERT INTO runtime_outbox
         (id, session_id, session_sequence, kind, payload_json,
          status, attempts, created_at_ms)
       VALUES (?, ?, ?, 'runtime.authorization.fence', ?, 'pending', 0, 100)`
    ).run(
      `retired-binding-fence-generation-${generation}`,
      SESSION_ID,
      sequence,
      JSON.stringify({
        sessionId: SESSION_ID,
        reason: "assignee-loss",
        runtimeAuthorizationGeneration: generation,
      })
    );
  }
  db.prepare(`UPDATE sessions SET next_sequence = 4 WHERE id = ?`).run(SESSION_ID);
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
  const hasEnforcerSet = hasColumn(
    db,
    "runtime_run_commands",
    "required_effect_enforcer_set_digest"
  );
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
      ...(hasEnforcerSet ? { requiredEffectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST } : {}),
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
              ...(hasEnforcerSet
                ? { requiredEffectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST }
                : {}),
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
          ${hasEnforcerSet ? "required_effect_enforcer_set_digest," : ""}
          source_session_sequence, command_json, command_digest, authority_digest,
          created_at_ms, deadline_at_ms)
       VALUES (?, ?, 'run-1', ?, ?, ?, ?, 1, ?, 1, 'goal-set-1', 1,
               ?, 1, 'sandbox-1', ?, 'principal-1', 1,
               ${hasEnforcerSet ? "?," : ""}
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
      ...(hasEnforcerSet ? [EFFECT_ENFORCER_SET_DIGEST] : []),
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
  const hasEnforcementProofColumns = hasColumn(
    db,
    "runtime_run_command_receipts",
    "aggregate_proof_digest"
  );
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
  const effectRef = hasEnforcementProofColumns
    ? `effect:v1:${digestFor("runtime-command-1-effect")}`
    : "effect:runtime-command-1";
  const originalEffectRef = hasEnforcementProofColumns
    ? `effect:v1:${digestFor("original-effect")}`
    : "effect:original";
  const originalOutcomeProof =
    originalOutcome === "accepted"
      ? options.incompleteOriginalProof
        ? {}
        : { effectRef: originalEffectRef }
      : originalOutcome === "enforced"
        ? options.incompleteOriginalProof
          ? { enforcedFence: 2 }
          : {
              enforcedFence: 2,
              effectRef: originalEffectRef,
              ...(hasEnforcementProofColumns
                ? { aggregateEnforcementProof: schemaAggregateProof() }
                : {}),
            }
        : originalOutcome === "rejected"
          ? options.incompleteOriginalProof
            ? { code: "stale_fence" }
            : { code: "stale_fence", safeDetail: "The fence is stale" }
          : originalOutcome === "quarantined"
            ? options.incompleteOriginalProof
              ? { reason: "isolation_failure" }
              : { reason: "isolation_failure", effectRef: originalEffectRef }
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
              effectRef,
              ...(hasEnforcementProofColumns
                ? { aggregateEnforcementProof: schemaAggregateProof() }
                : {}),
            }
          : outcome === "accepted"
            ? { ...receiptBase, effectRef }
            : outcome === "rejected"
              ? { ...receiptBase, code: "stale_fence", safeDetail: "The fence is stale" }
              : outcome === "quarantined"
                ? {
                    ...receiptBase,
                    reason: "isolation_failure",
                    effectRef,
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
          receipt_json, receipt_digest, received_at_ms${
            hasEnforcementProofColumns
              ? `, required_effect_enforcer_set_digest, enforcement_subject_digest,
                 aggregate_proof_digest, proof_verified_at_ms`
              : ""
          })
       VALUES (?, ?, ?, ?, ?, 'run-1', 1, 1, 'goal-set-1', 1,
               ?, 1, 'sandbox-1', 1, 'principal-1', 1, 1, 2, 1,
               ?, ?, ?, ?, ?, ?, 110${hasEnforcementProofColumns ? ", ?, ?, ?, ?" : ""})`
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
      receiptDigest,
      ...(hasEnforcementProofColumns
        ? effectiveOutcome(outcome, originalOutcome) === "enforced"
          ? [EFFECT_ENFORCER_SET_DIGEST, ENFORCEMENT_SUBJECT_DIGEST, AGGREGATE_PROOF_DIGEST, 110]
          : [null, null, null, null]
        : [])
    );
}

function effectiveOutcome(
  outcome: "accepted" | "enforced" | "duplicate" | "rejected" | "quarantined",
  originalOutcome: "accepted" | "enforced" | "rejected" | "quarantined" | null
) {
  return outcome === "duplicate" ? originalOutcome : outcome;
}

function insertRuntimeCompensationIncident(
  db: Database.Database,
  options: {
    compensationId?: string;
    incidentDigest?: string;
    commandId?: string;
    receiptId?: string;
  } = {}
): void {
  const compensationId = options.compensationId ?? "compensation-1";
  const incidentDigest = options.incidentDigest ?? digestFor("compensation-incident-1");
  const commandId = options.commandId ?? "runtime-command-1";
  const receiptId = options.receiptId ?? "receipt-1";
  const source = db
    .prepare(
      `SELECT json_extract(
         receipt_json,
         CASE WHEN outcome = 'duplicate'
           THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
       ) AS source_enforced_fence
       FROM runtime_run_command_receipts WHERE id = ?`
    )
    .get(receiptId) as { source_enforced_fence: number };
  const allocation = db
    .prepare(
      `UPDATE runtime_binding_safety_fences
       SET allocated_fence = MAX(allocated_fence, ?) + 1, updated_at_ms = 110
       WHERE runtime_assignment_id = ? AND runtime_assignment_generation = 1
       RETURNING allocated_fence`
    )
    .get(source.source_enforced_fence, ASSIGNMENT_ID) as { allocated_fence: number };
  db.prepare(
    `INSERT INTO runtime_compensation_incidents (
       compensation_id, incident_digest, source_command_id, source_receipt_id, trust_state,
       session_id, team_id, project_id, agent_run_id, run_policy_revision,
       runtime_assignment_id, runtime_assignment_generation,
       sandbox_id, sandbox_generation, runtime_principal_id,
       runtime_authorization_generation, source_command_digest,
       lifecycle_command_claims_digest, lifecycle_receipt_digest,
       source_enforced_fence, safety_fence,
       source_effect_ref_commitment, source_required_effect_enforcer_set_digest,
       lifecycle_enforcement_subject_digest, lifecycle_aggregate_proof_digest,
       source_proof_verified_at_ms, created_at_ms
     )
     SELECT ?, ?, command.id, receipt.id, 'verified',
       command.session_id, assignment.team_id, assignment.project_id,
       command.agent_run_id, command.run_policy_revision,
       command.runtime_assignment_id, command.runtime_assignment_generation,
       command.sandbox_id, command.sandbox_generation, command.runtime_principal_id,
       command.runtime_authorization_generation, command.command_digest,
       command.authority_digest, receipt.receipt_digest,
       json_extract(
         receipt.receipt_json,
         CASE WHEN receipt.outcome = 'duplicate'
           THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
       ),
       ?,
       json_extract(
         receipt.receipt_json,
         CASE WHEN receipt.outcome = 'duplicate'
           THEN '$.originalReceipt.effectRef' ELSE '$.effectRef' END
       ),
       command.required_effect_enforcer_set_digest,
       receipt.enforcement_subject_digest, receipt.aggregate_proof_digest,
       receipt.proof_verified_at_ms, receipt.received_at_ms
     FROM runtime_run_commands command
     JOIN runtime_assignments assignment ON assignment.id = command.runtime_assignment_id
     JOIN runtime_run_command_receipts receipt ON receipt.command_id = command.id
     WHERE command.id = ? AND receipt.id = ?`
  ).run(compensationId, incidentDigest, allocation.allocated_fence, commandId, receiptId);
}

function insertRuntimeCompensationCommand(db: Database.Database): void {
  const incident = db
    .prepare(`SELECT * FROM runtime_compensation_incidents WHERE compensation_id = ?`)
    .get("compensation-1") as Record<string, string | number>;
  const authorityDigest = digestFor("compensation-authority-1");
  const commandDigest = digestFor("compensation-command-1");
  const binding = {
    teamId: incident.team_id,
    projectId: incident.project_id,
    sessionId: incident.session_id,
    runtimeAssignmentId: incident.runtime_assignment_id,
    runtimeAssignmentGeneration: incident.runtime_assignment_generation,
    sandboxId: incident.sandbox_id,
    sandboxGeneration: incident.sandbox_generation,
    runtimePrincipalId: incident.runtime_principal_id,
  };
  const commandJson = JSON.stringify({
    kind: "safety.quarantine",
    commandId: "compensation-command-1",
    compensationId: incident.compensation_id,
    binding,
    observedRuntimeAuthorizationGeneration: incident.runtime_authorization_generation,
    source: {
      lifecycleCommandId: incident.source_command_id,
      lifecycleCommandClaimsDigest: incident.lifecycle_command_claims_digest,
      lifecycleReceiptDigest: incident.lifecycle_receipt_digest,
      lifecycleEnforcementSubjectDigest: incident.lifecycle_enforcement_subject_digest,
      lifecycleAggregateProofDigest: incident.lifecycle_aggregate_proof_digest,
      sourceRequiredEffectEnforcerSetDigest: incident.source_required_effect_enforcer_set_digest,
    },
    platformSecurityPolicyRevision: "platform-security-policy-1",
    requiredContainmentEnforcerSetDigest: CONTAINMENT_ENFORCER_SET_DIGEST,
    containment: {
      revokeTerminalWrites: true,
      stopProcessExecution: true,
      quarantineRuntime: true,
    },
    safetyFence: incident.safety_fence,
    exactBindingOnly: true,
    advanceBeyondCurrentFences: true,
    reasonRef: incident.incident_digest,
    causationId: incident.source_command_id,
    actor: { kind: "system", actorRef: "platform-security" },
    issuedAtMs: 120,
    deadlineAtMs: 220,
    authority: {
      issuer: "platform-security",
      issuerKeyId: "platform-security-key-1",
      audience: "runtime",
      capability: "safety.quarantine",
      claimsDigest: authorityDigest,
      issuedAtMs: 120,
      expiresAtMs: 220,
      signature: "platform-security-signature",
    },
  });
  db.transaction(() => {
    db.prepare(
      `INSERT INTO runtime_compensation_commands (
         id, compensation_id, source_command_id, command_sequence, previous_command_sequence,
         operation, session_id, team_id, project_id, agent_run_id,
         runtime_assignment_id, runtime_assignment_generation,
         sandbox_id, sandbox_generation, runtime_principal_id,
         observed_runtime_authorization_generation,
         source_required_effect_enforcer_set_digest,
         lifecycle_command_claims_digest, lifecycle_receipt_digest,
         lifecycle_enforcement_subject_digest, lifecycle_aggregate_proof_digest,
         platform_security_policy_revision, required_containment_enforcer_set_digest,
         safety_fence, reason_ref, causation_id, command_json,
         command_digest, authority_digest, created_at_ms,
         authority_verified_at_ms, deadline_at_ms
       ) VALUES (
         'compensation-command-1', ?, ?, 1, NULL, 'safety.quarantine',
         ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
         'platform-security-policy-1', ?, ?, ?, ?, ?, ?, ?, 120, 121, 220
       )`
    ).run(
      incident.compensation_id,
      incident.source_command_id,
      incident.session_id,
      incident.team_id,
      incident.project_id,
      incident.agent_run_id,
      incident.runtime_assignment_id,
      incident.runtime_assignment_generation,
      incident.sandbox_id,
      incident.sandbox_generation,
      incident.runtime_principal_id,
      incident.runtime_authorization_generation,
      incident.source_required_effect_enforcer_set_digest,
      incident.lifecycle_command_claims_digest,
      incident.lifecycle_receipt_digest,
      incident.lifecycle_enforcement_subject_digest,
      incident.lifecycle_aggregate_proof_digest,
      CONTAINMENT_ENFORCER_SET_DIGEST,
      incident.safety_fence,
      incident.incident_digest,
      incident.source_command_id,
      commandJson,
      commandDigest,
      authorityDigest
    );
    db.prepare(
      `INSERT INTO runtime_compensation_dispatch (
         compensation_command_id, compensation_id, source_command_id,
         status, attempts, available_at_ms, created_at_ms, updated_at_ms
       ) VALUES (
         'compensation-command-1', ?, ?, 'pending', 0, 120, 120, 120
       )`
    ).run(incident.compensation_id, incident.source_command_id);
  })();
}

function seedPendingRuntimeCompensationCommand(db: Database.Database): void {
  seedRuntimeRunCommand(db);
  claimRuntimeRunDispatch(db, "runtime-command-1");
  insertRuntimeRunReceipt(db);
  insertRuntimeCompensationIncident(db);
  db.prepare(
    `UPDATE runtime_run_command_dispatch
     SET status = 'compensating', lease_owner = NULL, lease_expires_at_ms = NULL,
         updated_at_ms = 110
     WHERE command_id = 'runtime-command-1'`
  ).run();
  insertRuntimeCompensationCommand(db);
}

function interlockRuntimeCompensationDispatch(db: Database.Database): void {
  db.prepare(
    `UPDATE runtime_compensation_dispatch
     SET status = 'processing', attempts = 1, lease_owner = 'security-worker-1',
         lease_expires_at_ms = 220, updated_at_ms = 121
     WHERE compensation_command_id = 'compensation-command-1'`
  ).run();
  db.prepare(
    `UPDATE runtime_compensation_dispatch
     SET dispatch_interlock_acquired_at_ms = 122, updated_at_ms = 122
     WHERE compensation_command_id = 'compensation-command-1'`
  ).run();
}

function runtimeCompensationDispatchState(db: Database.Database): Record<string, unknown> {
  return db
    .prepare(`SELECT * FROM runtime_compensation_dispatch WHERE compensation_command_id = ?`)
    .get("compensation-command-1") as Record<string, unknown>;
}

function runtimeCompensationDuplicateReceiptJson(db: Database.Database): string {
  const command = db
    .prepare(`SELECT * FROM runtime_compensation_commands WHERE id = ?`)
    .get("compensation-command-1") as Record<string, string | number>;
  const binding = {
    teamId: command.team_id,
    projectId: command.project_id,
    sessionId: command.session_id,
    runtimeAssignmentId: command.runtime_assignment_id,
    runtimeAssignmentGeneration: command.runtime_assignment_generation,
    sandboxId: command.sandbox_id,
    sandboxGeneration: command.sandbox_generation,
    runtimePrincipalId: command.runtime_principal_id,
  };
  const originalReceipt = {
    receiptKind: "runtime.compensation",
    compensationId: command.compensation_id,
    commandId: command.id,
    binding,
    observedRuntimeAuthorizationGeneration: command.observed_runtime_authorization_generation,
    outcome: "enforced",
    effectRef: `effect:v1:${digestFor("duplicate-compensation-effect-ref")}`,
    enforcedSafetyFence: command.safety_fence,
    containment: {
      terminalWritesRevoked: true,
      processExecutionStopped: true,
      runtimeQuarantined: true,
    },
    aggregateEnforcementProof: {
      generation: command.observed_runtime_authorization_generation,
      requiredEffectEnforcerSetDigest: CONTAINMENT_ENFORCER_SET_DIGEST,
      enforcementSubjectDigest: COMPENSATION_ENFORCEMENT_SUBJECT_DIGEST,
      acknowledgements: [
        {
          enforcerRef: "containment-enforcer-1",
          enforcerKind: "runtime",
          acknowledgementDigest: digestFor("duplicate-containment-ack-1"),
        },
      ],
      aggregateProofDigest: COMPENSATION_AGGREGATE_PROOF_DIGEST,
    },
  };
  return JSON.stringify({
    receiptKind: "runtime.compensation",
    compensationId: command.compensation_id,
    commandId: command.id,
    binding,
    observedRuntimeAuthorizationGeneration: command.observed_runtime_authorization_generation,
    outcome: "duplicate",
    originalReceipt,
    originalReceiptDigest: digestFor("duplicate-original-receipt"),
  });
}

function insertRuntimeCompensationDuplicateReceipt(
  db: Database.Database,
  receiptJson: string
): void {
  const command = db
    .prepare(`SELECT * FROM runtime_compensation_commands WHERE id = ?`)
    .get("compensation-command-1") as Record<string, string | number>;
  db.prepare(
    `INSERT INTO runtime_compensation_receipts (
       id, compensation_command_id, compensation_id, source_command_id,
       version, previous_version, session_id, team_id, project_id, agent_run_id,
       runtime_assignment_id, runtime_assignment_generation,
       sandbox_id, sandbox_generation, runtime_principal_id,
       observed_runtime_authorization_generation, command_digest,
       enforced_safety_fence, outcome, original_outcome, original_receipt_digest,
       receipt_json, receipt_digest, required_containment_enforcer_set_digest,
       effect_ref_commitment, enforcement_subject_digest, aggregate_proof_digest,
       proof_verified_at_ms, received_at_ms
     ) VALUES (
       'compensation-receipt-duplicate', 'compensation-command-1', ?, ?,
       1, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
       'duplicate', 'enforced', ?, ?, ?, ?, ?, ?, ?, 130, 130
     )`
  ).run(
    command.compensation_id,
    command.source_command_id,
    command.session_id,
    command.team_id,
    command.project_id,
    command.agent_run_id,
    command.runtime_assignment_id,
    command.runtime_assignment_generation,
    command.sandbox_id,
    command.sandbox_generation,
    command.runtime_principal_id,
    command.observed_runtime_authorization_generation,
    command.command_digest,
    command.safety_fence,
    digestFor("duplicate-original-receipt"),
    receiptJson,
    digestFor("duplicate-compensation-receipt"),
    CONTAINMENT_ENFORCER_SET_DIGEST,
    `effect:v1:${digestFor("duplicate-compensation-effect-ref")}`,
    COMPENSATION_ENFORCEMENT_SUBJECT_DIGEST,
    COMPENSATION_AGGREGATE_PROOF_DIGEST
  );
}

function insertRuntimeCompensationReceiptAndEffect(
  db: Database.Database,
  options: { advanceSafetyFence?: boolean } = {}
): void {
  const command = db
    .prepare(`SELECT * FROM runtime_compensation_commands WHERE id = ?`)
    .get("compensation-command-1") as Record<string, string | number>;
  const enforcedSafetyFence = Number(command.safety_fence) + 1;
  const effectRefCommitment = `effect:v1:${digestFor("compensation-effect-ref")}`;
  const receiptDigest = digestFor("compensation-receipt-1");
  const effectDigest = digestFor("compensation-effect-1");
  const binding = {
    teamId: command.team_id,
    projectId: command.project_id,
    sessionId: command.session_id,
    runtimeAssignmentId: command.runtime_assignment_id,
    runtimeAssignmentGeneration: command.runtime_assignment_generation,
    sandboxId: command.sandbox_id,
    sandboxGeneration: command.sandbox_generation,
    runtimePrincipalId: command.runtime_principal_id,
  };
  const receiptJson = JSON.stringify({
    receiptKind: "runtime.compensation",
    compensationId: command.compensation_id,
    commandId: command.id,
    binding,
    observedRuntimeAuthorizationGeneration: command.observed_runtime_authorization_generation,
    outcome: "enforced",
    effectRef: effectRefCommitment,
    enforcedSafetyFence,
    containment: {
      terminalWritesRevoked: true,
      processExecutionStopped: true,
      runtimeQuarantined: true,
    },
    aggregateEnforcementProof: {
      generation: command.observed_runtime_authorization_generation,
      requiredEffectEnforcerSetDigest: CONTAINMENT_ENFORCER_SET_DIGEST,
      enforcementSubjectDigest: COMPENSATION_ENFORCEMENT_SUBJECT_DIGEST,
      acknowledgements: [
        {
          enforcerRef: "containment-enforcer-1",
          enforcerKind: "runtime",
          acknowledgementDigest: digestFor("containment-ack-1"),
        },
      ],
      aggregateProofDigest: COMPENSATION_AGGREGATE_PROOF_DIGEST,
    },
  });
  db.transaction(() => {
    db.prepare(
      `INSERT INTO runtime_compensation_receipts (
         id, compensation_command_id, compensation_id, source_command_id,
         version, previous_version, session_id, team_id, project_id, agent_run_id,
         runtime_assignment_id, runtime_assignment_generation,
         sandbox_id, sandbox_generation, runtime_principal_id,
         observed_runtime_authorization_generation, command_digest,
         enforced_safety_fence, outcome, original_outcome, original_receipt_digest,
         receipt_json, receipt_digest, required_containment_enforcer_set_digest,
         effect_ref_commitment, enforcement_subject_digest, aggregate_proof_digest,
         proof_verified_at_ms, received_at_ms
       ) VALUES (
         'compensation-receipt-1', 'compensation-command-1', ?, ?,
         1, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
         'enforced', NULL, NULL, ?, ?, ?, ?, ?, ?, 130, 130
       )`
    ).run(
      command.compensation_id,
      command.source_command_id,
      command.session_id,
      command.team_id,
      command.project_id,
      command.agent_run_id,
      command.runtime_assignment_id,
      command.runtime_assignment_generation,
      command.sandbox_id,
      command.sandbox_generation,
      command.runtime_principal_id,
      command.observed_runtime_authorization_generation,
      command.command_digest,
      enforcedSafetyFence,
      receiptJson,
      receiptDigest,
      CONTAINMENT_ENFORCER_SET_DIGEST,
      effectRefCommitment,
      COMPENSATION_ENFORCEMENT_SUBJECT_DIGEST,
      COMPENSATION_AGGREGATE_PROOF_DIGEST
    );
    if (options.advanceSafetyFence !== false) {
      const advanced = db
        .prepare(
          `UPDATE runtime_binding_safety_fences
           SET allocated_fence = ?, updated_at_ms = 130
           WHERE team_id = ? AND project_id = ? AND session_id = ?
             AND runtime_assignment_id = ? AND runtime_assignment_generation = ?
             AND sandbox_id = ? AND sandbox_generation = ? AND runtime_principal_id = ?
             AND allocated_fence = ?`
        )
        .run(
          enforcedSafetyFence,
          command.team_id,
          command.project_id,
          command.session_id,
          command.runtime_assignment_id,
          command.runtime_assignment_generation,
          command.sandbox_id,
          command.sandbox_generation,
          command.runtime_principal_id,
          command.safety_fence
        );
      expect(advanced.changes).toBe(1);
    }
    db.prepare(
      `INSERT INTO session_events (
         session_id, sequence, event_id, type, occurred_at_ms,
         actor_kind, actor_user_id, actor_display_name,
         source_scope, source_key, payload_json
       ) VALUES (
         ?, 2, 'event:compensation-enforced', 'run.runtime-command.compensated', 140,
         'system', 'platform-security', 'Platform Security',
         'runtime-compensation', 'compensation-1', ?
       )`
    ).run(
      SESSION_ID,
      JSON.stringify({
        compensationId: command.compensation_id,
        sourceCommandId: command.source_command_id,
        compensationCommandId: command.id,
        receiptId: "compensation-receipt-1",
        effectDigest,
        agentRunId: command.agent_run_id,
      })
    );
    db.prepare(
      `INSERT INTO runtime_compensation_effects (
         compensation_id, source_command_id, compensation_command_id,
         receipt_id, receipt_outcome, session_id, agent_run_id,
         applied_session_sequence, effect_digest, applied_at_ms
       ) VALUES (
         ?, ?, 'compensation-command-1', 'compensation-receipt-1', 'enforced',
         ?, ?, 2, ?, 140
       )`
    ).run(
      command.compensation_id,
      command.source_command_id,
      command.session_id,
      command.agent_run_id,
      effectDigest
    );
  })();
}

function schemaAggregateProof() {
  return {
    generation: 1,
    requiredEffectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST,
    enforcementSubjectDigest: ENFORCEMENT_SUBJECT_DIGEST,
    acknowledgements: [
      {
        enforcerRef: "runtime-enforcer-1",
        enforcerKind: "runtime",
        acknowledgementDigest: "b".repeat(64),
      },
    ],
    aggregateProofDigest: AGGREGATE_PROOF_DIGEST,
  };
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

function seedSessionAndAssignment(
  db: Database.Database,
  options: { runtimeAuthorizationState?: "pending" | "enforced" | "quarantined" } = {}
): void {
  const runtimeAuthorizationState = options.runtimeAuthorizationState ?? "enforced";
  db.prepare(`INSERT INTO teams (id, name, created_at_ms) VALUES (?, 'Acme', 1)`).run(TEAM_ID);
  db.prepare(
    `INSERT INTO projects (id, team_id, name, created_at_ms) VALUES (?, ?, 'Terminal X', 1)`
  ).run(PROJECT_ID, TEAM_ID);
  db.prepare(
    `INSERT INTO sessions
       (id, team_id, project_id, name, status, steering_policy,
        runtime_authorization_state,
        runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
     VALUES (?, ?, ?, 'Session', 'active', 'shared',
       ?, 'local-tmux', 'trusted-shared-host', 'phase-four-schema', 0, 1)`
  ).run(SESSION_ID, TEAM_ID, PROJECT_ID, runtimeAuthorizationState);
  db.prepare(
    `INSERT INTO runtime_assignments
       (id, session_id, team_id, project_id, generation, runtime_kind,
        sandbox_id, sandbox_generation, runtime_principal_id,
        runtime_authorization_generation, status, created_at_ms)
     VALUES (?, ?, ?, ?, 1, 'local-tmux', 'sandbox-1', 1, 'principal-1', 1, 'ready', 2)`
  ).run(ASSIGNMENT_ID, SESSION_ID, TEAM_ID, PROJECT_ID);
  if (hasColumn(db, "runtime_authorization_epochs", "effect_enforcer_set_digest")) {
    db.prepare(
      `INSERT INTO runtime_authorization_epochs
         (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms,
          effect_enforcer_set_digest)
       VALUES (?, 1, ?, 1, 'sandbox-1', 1, 'principal-1', 2, ?)`
    ).run(SESSION_ID, ASSIGNMENT_ID, EFFECT_ENFORCER_SET_DIGEST);
  } else {
    db.prepare(
      `INSERT INTO runtime_authorization_epochs
         (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms)
       VALUES (?, 1, ?, 1, 'sandbox-1', 1, 'principal-1', 2)`
    ).run(SESSION_ID, ASSIGNMENT_ID);
  }
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
  if (hasColumn(db, "runtime_authorization_epochs", "effect_enforcer_set_digest")) {
    db.prepare(
      `INSERT INTO runtime_authorization_epochs
         (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms,
          effect_enforcer_set_digest)
       VALUES (?, 1, ?, 1, 'sandbox-2', 1, 'principal-2', 2, ?)`
    ).run(OTHER_SESSION_ID, OTHER_ASSIGNMENT_ID, EFFECT_ENFORCER_SET_DIGEST);
  } else {
    db.prepare(
      `INSERT INTO runtime_authorization_epochs
         (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms)
       VALUES (?, 1, ?, 1, 'sandbox-2', 1, 'principal-2', 2)`
    ).run(OTHER_SESSION_ID, OTHER_ASSIGNMENT_ID);
  }
}

function insertRun(
  db: Database.Database,
  runId: string,
  lifecycle: "active" | "paused" | "completed"
): void {
  const goalSetId = runId === "run-1" ? "goal-set-1" : `goal-set:${runId}`;
  const hasEnforcerSet = hasColumn(
    db,
    "run_policy_revisions",
    "required_effect_enforcer_set_digest"
  );
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
          runtime_authorization_generation${
            hasEnforcerSet ? ", required_effect_enforcer_set_digest" : ""
          }, yolo_confirmation_ref, created_at_ms)
       VALUES
         (?, ?, 1, NULL, ?, ?, 'autonomous', 'continue-until-all-goals-achieved',
          'scoped-policy-1', '[]', ?, ?, 1,
          'ceiling-1', ?, ?, 1, 'sandbox-1', 1, 'principal-1', 1${
            hasEnforcerSet ? ", ?" : ""
          }, NULL, 20)`
    ).run(
      runId,
      SESSION_ID,
      digestFor(`policy-snapshot:${runId}:1`),
      digestFor(`policy-body:${runId}:1`),
      JSON.stringify(completeLimits()),
      goalSetId,
      digestFor("project-ceiling"),
      ASSIGNMENT_ID,
      ...(hasEnforcerSet ? [EFFECT_ENFORCER_SET_DIGEST] : [])
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
  const hasEnforcerSet = hasColumn(
    db,
    "run_policy_revisions",
    "required_effect_enforcer_set_digest"
  );
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
        runtime_authorization_generation${
          hasEnforcerSet ? ", required_effect_enforcer_set_digest" : ""
        }, yolo_confirmation_ref, created_at_ms)
     VALUES
       ('run-1', ?, 2, 1, ?, ?, 'autonomous', 'continue-until-all-goals-achieved',
        'scoped-policy-1', '[]', ?, ?, 1,
        'ceiling-1', ?, ?, 1, ?, 1, ?, 1${hasEnforcerSet ? ", ?" : ""}, NULL, 20)`
  ).run(
    SESSION_ID,
    digestFor("policy-snapshot:run-1:2"),
    digestFor("policy-body:run-1:2"),
    JSON.stringify(limits),
    goalSetId,
    digestFor("project-ceiling"),
    assignmentId,
    sandboxId,
    runtimePrincipalId,
    ...(hasEnforcerSet ? [EFFECT_ENFORCER_SET_DIGEST] : [])
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
    initialized.db.exec(`
      DROP TRIGGER runtime_outbox_dispatch_interlock_valid_insert;
      DROP TRIGGER runtime_outbox_source_event_valid_insert;
    `);
    insertRuntimeRequestEvent(initialized.db, 1, "event:legacy-runtime-outbox", {
      commandId: "legacy-runtime-outbox-1",
      type: "session.started",
      payload: {
        sessionId: SESSION_ID,
        runtimeKind: "local-tmux",
        runtimeAuthorizationGeneration: 1,
        enforcementState: "pending",
      },
    });
    initialized.db
      .prepare(
        `INSERT INTO runtime_outbox
           (id, session_id, session_sequence, kind, payload_json, status, attempts,
            lease_owner, lease_expires_at_ms, last_error, created_at_ms, delivered_at_ms)
         VALUES ('legacy-runtime-outbox-1', ?, 1, 'runtime.session.ensure', ?,
                 'pending', 3, NULL, NULL, 'retryable_transport_timeout', 100, NULL)`
      )
      .run(
        SESSION_ID,
        JSON.stringify({
          sessionId: SESSION_ID,
          runtimeKind: "local-tmux",
          tmuxName: "phase-four-schema",
          runtimeAuthorizationGeneration: 1,
        })
      );
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
      DROP TRIGGER IF EXISTS run_policy_revisions_enforcer_set_binding;
      DROP TRIGGER IF EXISTS sessions_runtime_lifecycle_dispatch_interlock;
      DROP TRIGGER IF EXISTS runtime_assignments_lifecycle_dispatch_interlock;
      DROP TRIGGER IF EXISTS agent_runs_lifecycle_dispatch_interlock;
      DROP TRIGGER IF EXISTS runtime_assignments_create_binding_safety_fence;
      DROP TRIGGER IF EXISTS runtime_outbox_dispatch_interlock_valid_insert;
      DROP TRIGGER IF EXISTS runtime_outbox_dispatch_interlock_valid_update;
      DROP TRIGGER IF EXISTS runtime_outbox_payload_valid_insert;
      DROP TRIGGER IF EXISTS runtime_outbox_immutable_update;
      DROP TRIGGER IF EXISTS runtime_outbox_immutable_delete;
      DROP TRIGGER IF EXISTS runtime_outbox_source_event_immutable_update;
      DROP TRIGGER IF EXISTS runtime_outbox_source_event_immutable_delete;
      DROP TRIGGER IF EXISTS runtime_outbox_source_event_valid_insert;
      DROP TRIGGER IF EXISTS runtime_outbox_mutation_valid_update;
      DROP TRIGGER IF EXISTS runtime_outbox_settlements_valid_insert;
      DROP TRIGGER IF EXISTS runtime_outbox_settlements_immutable_update;
      DROP TRIGGER IF EXISTS runtime_outbox_settlements_immutable_delete;
      DROP TRIGGER IF EXISTS runtime_outbox_supersession_evidence_valid_insert;
      DROP TRIGGER IF EXISTS runtime_outbox_supersession_evidence_immutable_update;
      DROP TRIGGER IF EXISTS runtime_outbox_supersession_evidence_immutable_delete;
      DROP TRIGGER IF EXISTS accepted_commands_runtime_outbox_evidence;
      DROP TRIGGER IF EXISTS accepted_commands_immutable_update;
      DROP TRIGGER IF EXISTS accepted_commands_immutable_delete;
      DROP TABLE runtime_outbox_supersession_evidence;
      DROP TABLE runtime_outbox_settlements;
      DROP INDEX runtime_outbox_dispatch_interlock_acquired_at_idx;
      DROP INDEX runtime_outbox_created_at_idx;
      ALTER TABLE runtime_outbox DROP COLUMN dispatch_interlock_acquired_at_ms;
      ALTER TABLE runtime_outbox DROP COLUMN dispatch_interlock_attempt;
      DROP TRIGGER IF EXISTS runtime_compensation_referenced_events_immutable_update;
      DROP TRIGGER IF EXISTS runtime_compensation_referenced_events_immutable_delete;
      DROP TABLE runtime_compensation_follow_events;
      DROP TABLE runtime_compensation_effects;
      DROP TABLE runtime_compensation_receipts;
      DROP TABLE runtime_compensation_dispatch;
      DROP TABLE runtime_compensation_commands;
      DROP TABLE runtime_compensation_incidents;
      DROP TABLE runtime_binding_safety_fences;
      DROP TABLE runtime_receipt_follow_events;
      DROP TABLE runtime_receipt_follow_streams;
      DROP TABLE runtime_principal_observation_keys;
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

function createRuntimeReceiptFollowSchemaV5Fixture(filename: string): void {
  const pragmaDescriptor = Object.getOwnPropertyDescriptor(Database.prototype, "pragma");
  if (!pragmaDescriptor?.value) throw new Error("Expected better-sqlite3 pragma method");
  let committedVersionFive = false;
  let stoppedBeforeVersionSix = false;
  Object.defineProperty(Database.prototype, "pragma", {
    ...pragmaDescriptor,
    value(this: Database.Database, source: string, ...args: unknown[]) {
      if (committedVersionFive && source === "user_version") {
        stoppedBeforeVersionSix = true;
        throw new Error("stop-after-v5-for-migration-fixture");
      }
      const result = Reflect.apply(pragmaDescriptor.value, this, [source, ...args]);
      if (source === "user_version = 5") committedVersionFive = true;
      return result;
    },
  });
  try {
    expect(() => openTeamSessionDatabase({ filename })).toThrow(
      /stop-after-v5-for-migration-fixture/
    );
  } finally {
    Object.defineProperty(Database.prototype, "pragma", pragmaDescriptor);
  }
  if (!committedVersionFive || !stoppedBeforeVersionSix) {
    throw new Error("Expected initializer to stop at committed schema v5");
  }
}

function createRuntimeCompensationSchemaV6Fixture(filename: string): void {
  const pragmaDescriptor = Object.getOwnPropertyDescriptor(Database.prototype, "pragma");
  if (!pragmaDescriptor?.value) throw new Error("Expected better-sqlite3 pragma method");
  let committedVersionSix = false;
  let stoppedBeforeVersionSeven = false;
  Object.defineProperty(Database.prototype, "pragma", {
    ...pragmaDescriptor,
    value(this: Database.Database, source: string, ...args: unknown[]) {
      if (committedVersionSix && source === "user_version") {
        stoppedBeforeVersionSeven = true;
        throw new Error("stop-after-v6-for-migration-fixture");
      }
      const result = Reflect.apply(pragmaDescriptor.value, this, [source, ...args]);
      if (source === "user_version = 6") committedVersionSix = true;
      return result;
    },
  });
  try {
    expect(() => openTeamSessionDatabase({ filename })).toThrow(
      /stop-after-v6-for-migration-fixture/
    );
  } finally {
    Object.defineProperty(Database.prototype, "pragma", pragmaDescriptor);
  }
  if (!committedVersionSix || !stoppedBeforeVersionSeven) {
    throw new Error("Expected initializer to stop at committed schema v6");
  }
}

function createRuntimeAssignmentOutboxSchemaV7Fixture(filename: string): void {
  const pragmaDescriptor = Object.getOwnPropertyDescriptor(Database.prototype, "pragma");
  if (!pragmaDescriptor?.value) throw new Error("Expected better-sqlite3 pragma method");
  let committedVersionSeven = false;
  let stoppedBeforeVersionEight = false;
  Object.defineProperty(Database.prototype, "pragma", {
    ...pragmaDescriptor,
    value(this: Database.Database, source: string, ...args: unknown[]) {
      if (committedVersionSeven && source === "user_version") {
        stoppedBeforeVersionEight = true;
        throw new Error("stop-after-v7-for-migration-fixture");
      }
      const result = Reflect.apply(pragmaDescriptor.value, this, [source, ...args]);
      if (source === "user_version = 7") committedVersionSeven = true;
      return result;
    },
  });
  try {
    expect(() => openTeamSessionDatabase({ filename })).toThrow(
      /stop-after-v7-for-migration-fixture/
    );
  } finally {
    Object.defineProperty(Database.prototype, "pragma", pragmaDescriptor);
  }
  if (!committedVersionSeven || !stoppedBeforeVersionEight) {
    throw new Error("Expected initializer to stop at committed schema v7");
  }
}

type RuntimeOutboxV7Status = "pending" | "processing" | "delivered" | "superseded" | "failed";

interface RuntimeOutboxV7FixtureOptions {
  outboxId: string;
  kind?: "runtime.session.ensure" | "runtime.session.retire" | "runtime.authorization.fence";
  payloadJson?: string;
  eventType?: string;
  eventPayload?: Record<string, unknown>;
  eventPayloadJson?: string;
  status?: RuntimeOutboxV7Status;
  attempts?: number;
  leaseOwner?: string | null;
  leaseExpiresAtMs?: number | null;
  lastError?: string | null;
  createdAtMs?: number;
  deliveredAtMs?: number | null;
}

function seedRuntimeOutboxV7Fixture(
  filename: string,
  options: RuntimeOutboxV7FixtureOptions
): void {
  createRuntimeAssignmentOutboxSchemaV7Fixture(filename);
  const legacy = new Database(filename);
  try {
    legacy.pragma("foreign_keys = ON");
    seedSessionAndAssignment(legacy);
    const createdAtMs = options.createdAtMs ?? 100;
    const eventId = `event:${options.outboxId}`;
    legacy
      .prepare(
        `INSERT INTO session_events
           (session_id, sequence, event_id, type, occurred_at_ms,
            actor_kind, actor_user_id, actor_display_name,
            source_scope, source_key, payload_json)
         VALUES (?, 1, ?, ?, ?, 'system', 'migration-fixture', 'Migration Fixture',
                 'vitest:migration', ?, ?)`
      )
      .run(
        SESSION_ID,
        eventId,
        options.eventType ?? "session.started",
        createdAtMs,
        eventId,
        options.eventPayloadJson ??
          JSON.stringify(
            options.eventPayload ?? {
              sessionId: SESSION_ID,
              runtimeKind: "local-tmux",
              runtimeAuthorizationGeneration: 1,
              enforcementState: "pending",
            }
          )
      );
    legacy
      .prepare(
        `INSERT INTO runtime_outbox
           (id, session_id, session_sequence, kind, payload_json, status, attempts,
            lease_owner, lease_expires_at_ms, last_error, created_at_ms, delivered_at_ms)
         VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        options.outboxId,
        SESSION_ID,
        options.kind ?? "runtime.session.ensure",
        options.payloadJson ??
          JSON.stringify({
            sessionId: SESSION_ID,
            runtimeKind: "local-tmux",
            tmuxName: "phase-four-schema",
            runtimeAuthorizationGeneration: 1,
          }),
        options.status ?? "pending",
        options.attempts ?? 0,
        options.leaseOwner ?? null,
        options.leaseExpiresAtMs ?? null,
        options.lastError ?? null,
        createdAtMs,
        options.deliveredAtMs ?? null
      );
  } finally {
    legacy.close();
  }
}

function expectRuntimeOutboxV7MigrationRollback(
  filename: string,
  options: { outboxId: string; expectedError: string; payloadJson?: string }
): void {
  let migrationError: unknown;
  try {
    openTeamSessionDatabase({ filename });
  } catch (error) {
    migrationError = error;
  }
  expect(migrationError).toBeInstanceOf(Error);
  expect((migrationError as Error).message).toBe(options.expectedError);
  if (options.payloadJson !== undefined) {
    expect((migrationError as Error).message).not.toContain(options.payloadJson);
  }

  const after = new Database(filename, { readonly: true });
  try {
    expect(after.pragma("user_version", { simple: true })).toBe(7);
    expect(hasColumn(after, "runtime_outbox", "dispatch_interlock_attempt")).toBe(false);
    expect(hasColumn(after, "runtime_outbox", "dispatch_interlock_acquired_at_ms")).toBe(false);
    expect(
      after.prepare(`SELECT id FROM runtime_outbox WHERE id = ?`).get(options.outboxId)
    ).toEqual({ id: options.outboxId });
    expect(
      after
        .prepare(
          `SELECT COUNT(*) AS count FROM sqlite_schema
           WHERE type = 'trigger' AND name LIKE 'runtime_outbox_%'`
        )
        .get()
    ).toEqual({ count: 0 });
    expect(after.pragma("foreign_key_check")).toEqual([]);
    expect(after.pragma("quick_check", { simple: true })).toBe("ok");
  } finally {
    after.close();
  }
}

function hasColumn(db: Database.Database, table: string, column: string): boolean {
  return (db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).some(
    (entry) => entry.name === column
  );
}
