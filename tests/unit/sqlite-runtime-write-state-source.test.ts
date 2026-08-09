import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  RuntimeWriteStateSnapshotError,
  createSqliteRuntimeWriteStateSnapshotSource,
} from "../../src/lib/team-sessions/sqlite-runtime-write-state-source";

describe("SqliteRuntimeWriteStateSnapshotSource", () => {
  let db: Database.Database;

  beforeEach(() => {
    db = new Database(":memory:");
    db.exec(`
      CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        runtime_authorization_generation INTEGER NOT NULL,
        runtime_authorization_state TEXT NOT NULL
      ) STRICT;
      CREATE TABLE runtime_assignments (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        status TEXT NOT NULL,
        runtime_authorization_generation INTEGER NOT NULL,
        UNIQUE (session_id, generation)
      ) STRICT;
    `);
  });

  afterEach(() => db.close());

  function session(
    id: string,
    status: "active" | "awaiting_assignee" | "ended",
    generation: number,
    authorizationState: "enforced" | "pending" | "quarantined"
  ) {
    db.prepare(
      `INSERT INTO sessions
         (id, status, runtime_authorization_generation, runtime_authorization_state)
       VALUES (?, ?, ?, ?)`
    ).run(id, status, generation, authorizationState);
  }

  function assignment(
    id: string,
    sessionId: string,
    generation: number,
    authorizationGeneration: number,
    status:
      | "provisioning"
      | "ready"
      | "checkpointing"
      | "recovering"
      | "quarantined"
      | "retired"
      | "failed"
  ) {
    db.prepare(
      `INSERT INTO runtime_assignments
         (id, session_id, generation, status, runtime_authorization_generation)
       VALUES (?, ?, ?, ?, ?)`
    ).run(id, sessionId, generation, status, authorizationGeneration);
  }

  it("reconstructs active, fenced, and retired states from one ordered durable snapshot", () => {
    session("active-session", "active", 3, "enforced");
    assignment("active-assignment", "active-session", 1, 3, "ready");

    session("pending-session", "active", 4, "pending");
    assignment("pending-assignment", "pending-session", 1, 4, "ready");

    session("ended-session", "ended", 5, "quarantined");
    assignment("ended-assignment", "ended-session", 1, 5, "quarantined");

    session("awaiting-session", "awaiting_assignee", 6, "enforced");

    const result = createSqliteRuntimeWriteStateSnapshotSource({ db }).read();
    expect(result).toEqual([
      {
        sessionId: "active-session",
        runtimeAuthorizationGeneration: 3,
        state: "active",
      },
      {
        sessionId: "awaiting-session",
        runtimeAuthorizationGeneration: 6,
        state: "fenced",
      },
      {
        sessionId: "ended-session",
        runtimeAuthorizationGeneration: 5,
        state: "retired",
      },
      {
        sessionId: "pending-session",
        runtimeAuthorizationGeneration: 4,
        state: "fenced",
      },
    ]);
    expect(Object.isFrozen(result)).toBe(true);
    expect(result.every(Object.isFrozen)).toBe(true);
  });

  it("uses the newest assignment and never rolls its authorization high-water backward", () => {
    session("session-one", "active", 6, "enforced");
    assignment("assignment-old", "session-one", 1, 9, "ready");
    assignment("assignment-new", "session-one", 2, 7, "quarantined");

    expect(createSqliteRuntimeWriteStateSnapshotSource({ db }).read()).toEqual([
      {
        sessionId: "session-one",
        runtimeAuthorizationGeneration: 9,
        state: "fenced",
      },
    ]);
  });

  it("does not classify a ready latest assignment active below historical high-water", () => {
    session("session-one", "active", 6, "enforced");
    assignment("assignment-old", "session-one", 1, 9, "retired");
    assignment("assignment-new", "session-one", 2, 6, "ready");

    expect(createSqliteRuntimeWriteStateSnapshotSource({ db }).read()).toEqual([
      {
        sessionId: "session-one",
        runtimeAuthorizationGeneration: 9,
        state: "fenced",
      },
    ]);
  });

  it("treats a retired assignment as terminal even before Session archival finishes", () => {
    session("session-one", "active", 8, "quarantined");
    assignment("assignment-one", "session-one", 1, 8, "retired");

    expect(createSqliteRuntimeWriteStateSnapshotSource({ db }).read()).toEqual([
      {
        sessionId: "session-one",
        runtimeAuthorizationGeneration: 8,
        state: "retired",
      },
    ]);
  });

  it("fails with a safe code for malformed durable rows and invalid configuration", () => {
    db.prepare(
      `INSERT INTO sessions
         (id, status, runtime_authorization_generation, runtime_authorization_state)
       VALUES ('session-one', 'unexpected', 1, 'enforced')`
    ).run();

    expect(() => createSqliteRuntimeWriteStateSnapshotSource({ db }).read()).toThrow(
      expect.objectContaining({ code: "journal_conflict" })
    );
    expect(() => createSqliteRuntimeWriteStateSnapshotSource({ db: null as never })).toThrow(
      expect.objectContaining({ code: "invalid_configuration" })
    );
    try {
      createSqliteRuntimeWriteStateSnapshotSource({ db }).read();
    } catch (error) {
      expect(error).toBeInstanceOf(RuntimeWriteStateSnapshotError);
      expect(String(error)).not.toContain("unexpected");
    }
  });

  it("rejects accessor-backed configuration and rows without invoking getters", () => {
    let getterCalls = 0;
    const hostileOptions = Object.defineProperty({}, "db", {
      enumerable: true,
      get() {
        getterCalls += 1;
        throw new Error("provider-secret-database-getter");
      },
    });
    expect(() => createSqliteRuntimeWriteStateSnapshotSource(hostileOptions as never)).toThrow(
      expect.objectContaining({ code: "invalid_configuration" })
    );
    expect(getterCalls).toBe(0);

    const hostileRow = Object.defineProperty(
      {
        session_id: "session-one",
        session_status: "active",
        session_authorization_generation: 1,
        session_authorization_state: "enforced",
        assignment_authorization_generation: 1,
        assignment_authorization_high_water: 1,
      },
      "assignment_status",
      {
        enumerable: true,
        get() {
          getterCalls += 1;
          throw new Error("provider-secret-row-getter");
        },
      }
    );
    const fakeDb = {
      prepare() {
        return { all: () => [hostileRow] };
      },
      transaction<T>(callback: () => T) {
        return { immediate: callback };
      },
    };
    let failure: unknown;
    try {
      createSqliteRuntimeWriteStateSnapshotSource({ db: fakeDb as never }).read();
    } catch (error) {
      failure = error;
    }
    expect(failure).toMatchObject({
      code: "journal_conflict",
      message: "Runtime write-state snapshot conflicts with durable state",
    });
    expect(String(failure)).not.toContain("provider-secret");
    expect(getterCalls).toBe(0);

    const throwingDb = {
      prepare() {
        return { all: () => [] };
      },
      transaction() {
        throw new Error("provider-secret-transaction-construction");
      },
    };
    expect(() =>
      createSqliteRuntimeWriteStateSnapshotSource({ db: throwingDb as never }).read()
    ).toThrow(
      expect.objectContaining({
        code: "journal_conflict",
        message: "Runtime write-state snapshot conflicts with durable state",
      })
    );
  });
});
