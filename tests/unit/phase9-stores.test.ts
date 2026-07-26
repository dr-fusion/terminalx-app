import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import type BetterSqlite3 from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import {
  createLimitLedgerStore,
  LimitLedgerError,
} from "@/lib/team-sessions/sqlite-limit-ledger-store";
import { createCircuitBreakerStateStore } from "@/lib/team-sessions/sqlite-circuit-breaker-store";
import {
  ApprovalProvenanceStoreError,
  createApprovalProvenanceStore,
} from "@/lib/team-sessions/sqlite-approval-provenance-store";
import { createYoloChallengeStore } from "@/lib/team-sessions/sqlite-yolo-challenge-store";
import { createRuntimeCircuitBreaker } from "@/lib/runtime/circuit-breaker";
import type { ResourceEffect, RunLimits } from "@/lib/team-sessions/contracts";
import type { YoloChallengeBinding } from "@/lib/runtime/yolo-challenge";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ASSIGNMENT_ID = "44444444-4444-4444-8444-444444444444";
const ENFORCER = "e".repeat(64);

function digestFor(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

const unlimited: RunLimits = {
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

function effect(overrides: Partial<ResourceEffect> = {}): ResourceEffect {
  return {
    wallClock: { milliseconds: 100 },
    modelTokens: 10,
    modelSpend: { currency: "USD", minorUnits: 5 },
    outboundBytes: 20,
    actionCounts: { local: 0, "scoped-external": 1, protected: 0, forbidden: 0 },
    ...overrides,
  };
}

function seedRun(db: BetterSqlite3.Database): void {
  db.prepare(`INSERT INTO teams (id, name, created_at_ms) VALUES (?, 'Acme', 1)`).run(TEAM_ID);
  db.prepare(`INSERT INTO projects (id, team_id, name, created_at_ms) VALUES (?, ?, 'TX', 1)`).run(
    PROJECT_ID,
    TEAM_ID
  );
  db.prepare(
    `INSERT INTO sessions
       (id, team_id, project_id, name, status, steering_policy, runtime_authorization_state,
        runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
     VALUES (?, ?, ?, 'S', 'active', 'shared', 'enforced',
       'local-tmux', 'trusted-shared-host', 'phase9', 0, 1)`
  ).run(SESSION_ID, TEAM_ID, PROJECT_ID);
  db.prepare(
    `INSERT INTO runtime_assignments
       (id, session_id, team_id, project_id, generation, runtime_kind, sandbox_id,
        sandbox_generation, runtime_principal_id, runtime_authorization_generation, status,
        created_at_ms)
     VALUES (?, ?, ?, ?, 1, 'local-tmux', 'sandbox-1', 1, 'principal-1', 1, 'ready', 2)`
  ).run(ASSIGNMENT_ID, SESSION_ID, TEAM_ID, PROJECT_ID);
  db.prepare(
    `INSERT INTO runtime_authorization_epochs
       (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
        sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms,
        effect_enforcer_set_digest, effect_enforcer_policy_digest)
     VALUES (?, 1, ?, 1, 'sandbox-1', 1, 'principal-1', 2, ?, ?)`
  ).run(SESSION_ID, ASSIGNMENT_ID, ENFORCER, ENFORCER);
  db.prepare(
    `INSERT INTO runtime_effect_enforcer_set_activations
       (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
        sandbox_id, sandbox_generation, runtime_principal_id, activation_kind,
        effect_enforcer_policy_digest, effect_enforcer_set_digest, activated_at_ms)
     VALUES (?, 1, ?, 1, 'sandbox-1', 1, 'principal-1', 'local-static', ?, ?, 2)`
  ).run(SESSION_ID, ASSIGNMENT_ID, ENFORCER, ENFORCER);
  db.transaction(() => {
    db.prepare(
      `INSERT INTO agent_runs
         (id, session_id, team_id, project_id, runtime_assignment_id, lifecycle,
          current_policy_revision, current_goal_set_revision, runtime_authorization_generation,
          created_by_user_id, created_at_ms, updated_at_ms, terminal_at_ms)
       VALUES ('run-1', ?, ?, ?, ?, 'active', 1, 1, 1, 'user-alice', 10, 10, NULL)`
    ).run(SESSION_ID, TEAM_ID, PROJECT_ID, ASSIGNMENT_ID);
    db.prepare(
      `INSERT INTO goal_sets (goal_set_id, agent_run_id, revision, previous_revision, digest, created_at_ms)
       VALUES ('goal-set-1', 'run-1', 1, NULL, ?, 20)`
    ).run(digestFor("goal-set"));
    db.prepare(
      `INSERT INTO run_policy_revisions
         (agent_run_id, session_id, revision, previous_revision, digest, policy_body_digest,
          mode, completion_policy, scoped_external_policy_ref, scoped_external_rules_json, limits_json,
          initial_goal_set_id, initial_goal_set_revision, project_ceiling_revision,
          project_ceiling_digest, runtime_assignment_id, runtime_assignment_generation, sandbox_id,
          sandbox_generation, runtime_principal_id, runtime_authorization_generation,
          required_effect_enforcer_set_digest, yolo_confirmation_ref, created_at_ms)
       VALUES ('run-1', ?, 1, NULL, ?, ?, 'autonomous', 'continue-until-all-goals-achieved',
         'scoped-1', '[]', ?, 'goal-set-1', 1, 'ceiling-1', ?, ?, 1, 'sandbox-1', 1, 'principal-1', 1,
         ?, NULL, 20)`
    ).run(
      SESSION_ID,
      digestFor("policy"),
      digestFor("policy-body"),
      JSON.stringify(unlimited),
      digestFor("ceiling"),
      ASSIGNMENT_ID,
      ENFORCER
    );
  })();
}

function seedGrant(
  db: BetterSqlite3.Database,
  spec: { grantId: string; approvalId: string; manifestId: string; effectKey: string }
): { manifestDigest: string } {
  const manifestDigest = digestFor(`manifest:${spec.manifestId}`);
  db.prepare(
    `INSERT INTO action_manifests
       (id, version, session_id, agent_run_id, digest, action_class, provider, operation,
        exact_target, action_schema_id, action_schema_version, action_schema_digest,
        canonical_effect_input_digest, effect_idempotency_key, expected_effect_json,
        expires_at_ms, created_at_ms)
     VALUES (?, 1, ?, 'run-1', ?, 'scoped-external', 'github', 'branch.push', 'repo:branch',
       'github.branch.push', 1, ?, ?, ?, '{}', 100, 30)`
  ).run(
    spec.manifestId,
    SESSION_ID,
    manifestDigest,
    digestFor(`schema:${spec.manifestId}`),
    digestFor(`effect-input:${spec.manifestId}`),
    spec.effectKey
  );
  const insertApproval = db.prepare(
    `INSERT INTO approval_requests
       (id, version, previous_version, request_digest, session_id, agent_run_id,
        run_policy_revision, runtime_assignment_id, runtime_assignment_generation, sandbox_id,
        sandbox_generation, runtime_principal_id, runtime_authorization_generation, action_class,
        provider, operation, exact_target, subject_kind, manifest_id, manifest_digest,
        action_pattern_json, action_pattern_digest, subject_digest, status, expires_at_ms,
        created_at_ms, resolved_at_ms, resolved_by_actor_ref)
     VALUES (?, ?, ?, ?, ?, 'run-1', 1, ?, 1, 'sandbox-1', 1, 'principal-1', 1, 'scoped-external',
       'github', 'branch.push', 'repo:branch', 'manifest', ?, ?, NULL, NULL, ?, ?, 100, 40, ?, ?)`
  );
  insertApproval.run(
    spec.approvalId,
    1,
    null,
    digestFor(`open:${spec.approvalId}`),
    SESSION_ID,
    ASSIGNMENT_ID,
    spec.manifestId,
    manifestDigest,
    manifestDigest,
    "open",
    null,
    null
  );
  insertApproval.run(
    spec.approvalId,
    2,
    1,
    digestFor(`approved:${spec.approvalId}`),
    SESSION_ID,
    ASSIGNMENT_ID,
    spec.manifestId,
    manifestDigest,
    manifestDigest,
    "approved",
    40,
    "user-alice"
  );
  db.prepare(
    `INSERT INTO action_grants
       (id, session_id, agent_run_id, run_policy_revision, runtime_assignment_id,
        runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id,
        runtime_authorization_generation, approval_request_id, approval_request_version,
        approval_status, approval_subject_kind, action_class, provider, operation, target,
        budget_json, usage_ledger_ref, scope_kind, scope_digest, manifest_digest,
        effect_idempotency_key, action_pattern_json, action_pattern_digest, eligible_run_use,
        issuer_actor_ref, issuer_approval_authority_revision, expires_at_ms, signature, created_at_ms)
     VALUES (?, ?, 'run-1', 1, ?, 1, 'sandbox-1', 1, 'principal-1', 1, ?, 2, 'approved', 'manifest',
       'scoped-external', 'github', 'branch.push', 'repo:branch', '{}', ?, 'once', ?, ?, ?, NULL,
       NULL, NULL, 'user-alice', 'authority-1', 90, 'sig', 50)`
  ).run(
    spec.grantId,
    SESSION_ID,
    ASSIGNMENT_ID,
    spec.approvalId,
    `ledger:${spec.grantId}`,
    manifestDigest,
    manifestDigest,
    spec.effectKey
  );
  db.prepare(
    `INSERT INTO action_grant_states (grant_id, version, previous_version, status, reason,
       actor_ref, created_at_ms)
     VALUES (?, 1, NULL, 'issued', 'issued', 'user-alice', 50)`
  ).run(spec.grantId);
  return { manifestDigest };
}

function seedGrantReview(db: BetterSqlite3.Database): void {
  db.prepare(
    `INSERT INTO grant_reviews
       (id, version, previous_version, session_id, agent_run_id, reason, safe_default, status,
        stale_grant_ids_json, intentionally_revoked_grant_ids_json,
        reissuable_candidate_grant_ids_json, target_run_policy_revision,
        target_runtime_assignment_id, target_runtime_assignment_generation, target_sandbox_id,
        target_sandbox_generation, target_runtime_principal_id,
        target_runtime_authorization_generation, created_at_ms)
     VALUES ('grant-review-1', 1, NULL, ?, 'run-1', 'runtime-authorization', 'revoke-all', 'open',
       '[]', '[]', '[]', 1, ?, 1, 'sandbox-1', 1, 'principal-1', 1, 60)`
  ).run(SESSION_ID, ASSIGNMENT_ID);
}

let handle: ReturnType<typeof openTeamSessionDatabase>;
let db: BetterSqlite3.Database;

beforeEach(() => {
  handle = openTeamSessionDatabase({ filename: ":memory:" });
  db = handle.db;
});

afterEach(() => {
  handle.close();
});

describe("Gate 5 — durable limit ledger", () => {
  it("reserves within limits, settles from a receipt, and never double-counts a duplicate receipt", () => {
    seedRun(db);
    const store = createLimitLedgerStore(db);
    const first = store.reserve({
      reservationId: "res-1",
      sessionId: SESSION_ID,
      agentRunId: "run-1",
      reserveReceiptDigest: digestFor("receipt-a"),
      request: effect({ modelTokens: 10 }),
      limits: { ...unlimited, modelTokens: { kind: "capped", value: 25 } },
      nowMs: 100,
    });
    expect(first).toMatchObject({ decision: { admitted: true } });
    // duplicate reserve receipt is idempotent — usage stays 10, not 20
    store.reserve({
      reservationId: "res-1-dup",
      sessionId: SESSION_ID,
      agentRunId: "run-1",
      reserveReceiptDigest: digestFor("receipt-a"),
      request: effect({ modelTokens: 10 }),
      limits: { ...unlimited, modelTokens: { kind: "capped", value: 25 } },
      nowMs: 100,
    });
    expect(store.committedUsage("run-1", "USD").modelTokens).toBe(10);

    store.settle({
      reservationId: "res-1",
      settleReceiptDigest: digestFor("settle-a"),
      actualUsage: effect({ modelTokens: 7 }),
      nowMs: 200,
    });
    // duplicate settle receipt idempotent
    store.settle({
      reservationId: "res-1",
      settleReceiptDigest: digestFor("settle-a"),
      actualUsage: effect({ modelTokens: 7 }),
      nowMs: 200,
    });
    expect(store.committedUsage("run-1", "USD").modelTokens).toBe(7);
  });

  it("denies a reservation that would exceed the cap and leaves the ledger unchanged", () => {
    seedRun(db);
    const store = createLimitLedgerStore(db);
    store.reserve({
      reservationId: "res-1",
      sessionId: SESSION_ID,
      agentRunId: "run-1",
      reserveReceiptDigest: digestFor("r1"),
      request: effect({ modelTokens: 20 }),
      limits: { ...unlimited, modelTokens: { kind: "capped", value: 25 } },
      nowMs: 100,
    });
    const denied = store.reserve({
      reservationId: "res-2",
      sessionId: SESSION_ID,
      agentRunId: "run-1",
      reserveReceiptDigest: digestFor("r2"),
      request: effect({ modelTokens: 10 }),
      limits: { ...unlimited, modelTokens: { kind: "capped", value: 25 } },
      nowMs: 100,
    });
    expect(denied).toEqual({ decision: { admitted: false, exceeded: ["model-tokens"] } });
    expect(store.committedUsage("run-1", "USD").modelTokens).toBe(20);
  });

  it("releases a reservation on failure so its headroom returns", () => {
    seedRun(db);
    const store = createLimitLedgerStore(db);
    store.reserve({
      reservationId: "res-1",
      sessionId: SESSION_ID,
      agentRunId: "run-1",
      reserveReceiptDigest: digestFor("r1"),
      request: effect({ modelTokens: 20 }),
      limits: unlimited,
      nowMs: 100,
    });
    expect(store.committedUsage("run-1", "USD").modelTokens).toBe(20);
    store.release({
      reservationId: "res-1",
      settleReceiptDigest: digestFor("rel-1"),
      currency: "USD",
      nowMs: 150,
    });
    expect(store.committedUsage("run-1", "USD").modelTokens).toBe(0);
    // cannot settle after release
    expect(() =>
      store.settle({
        reservationId: "res-1",
        settleReceiptDigest: digestFor("late"),
        actualUsage: effect(),
        nowMs: 200,
      })
    ).toThrow(LimitLedgerError);
  });

  it("treats unlimited as the explicit default and reports the read-model band", () => {
    seedRun(db);
    const store = createLimitLedgerStore(db);
    expect(store.limitStatus("run-1", unlimited, "USD")).toBe("within-configured-limits");
    store.reserve({
      reservationId: "res-1",
      sessionId: SESSION_ID,
      agentRunId: "run-1",
      reserveReceiptDigest: digestFor("r1"),
      request: effect({ modelTokens: 95 }),
      limits: { ...unlimited, modelTokens: { kind: "capped", value: 100 } },
      nowMs: 100,
    });
    expect(
      store.limitStatus(
        "run-1",
        { ...unlimited, modelTokens: { kind: "capped", value: 100 } },
        "USD"
      )
    ).toBe("approaching-90-percent");
    // unlimited stays within-configured no matter how large committed usage grows
    expect(store.limitStatus("run-1", unlimited, "USD")).toBe("within-configured-limits");
  });
});

describe("Gate 5 — durable circuit-breaker persistence across restart", () => {
  it("persists an open circuit and rehydrates it into a fresh breaker", () => {
    const store = createCircuitBreakerStateStore(db);
    const breaker = createRuntimeCircuitBreaker({ ttlMs: 100_000 });
    const failure = { operation: "sandbox.create", code: "runtime_timeout" };
    for (let i = 0; i < 3; i += 1) breaker.recordFailure("run-1", failure, 1_000);
    const snapshot = breaker.snapshotScope("run-1", 1_000)!;
    store.persistScope(snapshot, 1_000);

    const revived = createRuntimeCircuitBreaker({ ttlMs: 100_000 });
    for (const persisted of store.loadAll()) revived.loadScope(persisted, 2_000);
    expect(revived.status("run-1", 2_000).state).toBe("open");

    // an emptied scope is deleted, not persisted as an empty row
    store.deleteScope("run-1");
    expect(store.loadAll()).toHaveLength(0);
  });
});

describe("Gate 4 — approval provenance, lineage, and atomic consumption", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");

  function store() {
    return createApprovalProvenanceStore(db, {
      signingKey: privateKey,
      signingKeyId: "approval-key-1",
      verificationKeys: new Map([["approval-key-1", publicKey]]),
    });
  }

  it("signs immutable provenance that verifies and fails closed after tampering", () => {
    seedRun(db);
    const { manifestDigest } = seedGrant(db, {
      grantId: "grant-1",
      approvalId: "approval-1",
      manifestId: "manifest-1",
      effectKey: "effect-1",
    });
    const s = store();
    const proof = s.recordApprovalProvenance({
      grantId: "grant-1",
      approvalRequestId: "approval-1",
      approvalRequestVersion: 2,
      grantStateVersion: 1,
      actorKind: "human",
      actorRef: "user-alice",
      capability: {
        actionClass: "scoped-external",
        provider: "github",
        operation: "branch.push",
        target: "repo:branch",
        scopeKind: "once",
        scopeDigest: manifestDigest,
      },
      policyDigest: digestFor("policy"),
      budgetDigest: digestFor("budget"),
      binding: {
        teamId: TEAM_ID,
        projectId: PROJECT_ID,
        sessionId: SESSION_ID,
        runtimeAssignmentId: ASSIGNMENT_ID,
        runtimeAssignmentGeneration: 1,
        sandboxId: "sandbox-1",
        sandboxGeneration: 1,
        runtimePrincipalId: "principal-1",
      },
      runtimeAuthorizationGeneration: 1,
      issuedAtMs: 50,
      expiresAtMs: 90,
      nowMs: 60,
    });
    expect(proof.payload.grantId).toBe("grant-1");
    expect(s.verifyStoredProvenance("grant-1")).not.toBeNull();

    // provenance rows are immutable
    expect(() =>
      db
        .prepare("UPDATE approval_provenance SET budget_digest = ? WHERE grant_id = 'grant-1'")
        .run(digestFor("x"))
    ).toThrow(/immutable/);

    // a store with a different trusted key cannot authenticate the stored proof
    const foreign = generateKeyPairSync("ed25519");
    const foreignStore = createApprovalProvenanceStore(db, {
      signingKey: privateKey,
      signingKeyId: "approval-key-1",
      verificationKeys: new Map([["approval-key-1", foreign.publicKey]]),
    });
    expect(foreignStore.verifyStoredProvenance("grant-1")).toBeNull();
  });

  it("records append-only reissue lineage that cannot be mutated", () => {
    seedRun(db);
    seedGrant(db, {
      grantId: "grant-1",
      approvalId: "approval-1",
      manifestId: "m1",
      effectKey: "e1",
    });
    seedGrant(db, {
      grantId: "grant-2",
      approvalId: "approval-2",
      manifestId: "m2",
      effectKey: "e2",
    });
    seedGrantReview(db);
    const s = store();
    s.appendGrantLineage({
      lineageId: "lin-1",
      sessionId: SESSION_ID,
      agentRunId: "run-1",
      successorGrantId: "grant-2",
      predecessorGrantId: "grant-1",
      relation: "reissues",
      grantReviewId: "grant-review-1",
      grantReviewVersion: 1,
      actorRef: "user-alice",
      nowMs: 70,
    });
    expect(db.prepare("SELECT relation FROM grant_lineage WHERE id = 'lin-1'").get()).toEqual({
      relation: "reissues",
    });
    expect(() =>
      db.prepare("UPDATE grant_lineage SET relation = 'supersedes' WHERE id = 'lin-1'").run()
    ).toThrow(/append-only/);
    // self-lineage is rejected by the schema
    expect(() =>
      s.appendGrantLineage({
        lineageId: "lin-2",
        sessionId: SESSION_ID,
        agentRunId: "run-1",
        successorGrantId: "grant-1",
        predecessorGrantId: "grant-1",
        relation: "reissues",
        grantReviewId: "grant-review-1",
        grantReviewVersion: 1,
        actorRef: "user-alice",
        nowMs: 71,
      })
    ).toThrow();
  });

  it("consumes a grant exactly once and rejects a conflicting duplicate consumption", () => {
    seedRun(db);
    seedGrant(db, {
      grantId: "grant-1",
      approvalId: "approval-1",
      manifestId: "m1",
      effectKey: "e1",
    });
    const s = store();
    const first = s.consumeGrant({
      grantId: "grant-1",
      effectIdempotencyKey: "e1",
      canonicalEffectInputDigest: digestFor("effect-input"),
      consumptionReceiptDigest: digestFor("consume-1"),
      actorRef: "system",
      nowMs: 100,
    });
    expect(first).toEqual({ outcome: "consumed", grantStateVersion: 2 });

    // crash-retry with the identical receipt converges idempotently
    expect(
      s.consumeGrant({
        grantId: "grant-1",
        effectIdempotencyKey: "e1",
        canonicalEffectInputDigest: digestFor("effect-input"),
        consumptionReceiptDigest: digestFor("consume-1"),
        actorRef: "system",
        nowMs: 101,
      })
    ).toEqual({ outcome: "already-consumed", grantStateVersion: 2 });

    // a different effect against the consumed grant is a conflict
    expect(() =>
      s.consumeGrant({
        grantId: "grant-1",
        effectIdempotencyKey: "e1",
        canonicalEffectInputDigest: digestFor("other-effect"),
        consumptionReceiptDigest: digestFor("consume-2"),
        actorRef: "system",
        nowMs: 102,
      })
    ).toThrow(ApprovalProvenanceStoreError);

    // exactly one consumption row and a terminal consumed state
    expect(
      (db.prepare("SELECT COUNT(*) AS c FROM grant_consumptions").get() as { c: number }).c
    ).toBe(1);
    expect(
      db
        .prepare("SELECT status FROM action_grant_states WHERE grant_id='grant-1' AND version=2")
        .get()
    ).toEqual({ status: "consumed" });
  });

  it("invalidates every outstanding grant when the execution boundary changes", () => {
    seedRun(db);
    seedGrant(db, {
      grantId: "grant-1",
      approvalId: "approval-1",
      manifestId: "m1",
      effectKey: "e1",
    });
    seedGrant(db, {
      grantId: "grant-2",
      approvalId: "approval-2",
      manifestId: "m2",
      effectKey: "e2",
    });
    const s = store();
    const invalidated = s.invalidateOutstandingGrants({
      agentRunId: "run-1",
      reason: "sandbox-generation",
      actorRef: "system",
      nowMs: 120,
    });
    expect([...invalidated].sort()).toEqual(["grant-1", "grant-2"]);
    for (const grantId of invalidated) {
      const latest = db
        .prepare(
          "SELECT status, reason FROM action_grant_states WHERE grant_id=? ORDER BY version DESC LIMIT 1"
        )
        .get(grantId);
      expect(latest).toEqual({ status: "invalidated", reason: "sandbox-generation" });
    }
    // an already-consumed grant is not re-invalidated
    expect(
      s.invalidateOutstandingGrants({
        agentRunId: "run-1",
        reason: "sandbox-generation",
        actorRef: "system",
        nowMs: 121,
      })
    ).toEqual([]);
  });
});

describe("Gate 6 — YOLO challenge lifecycle", () => {
  function binding(overrides: Partial<YoloChallengeBinding> = {}): YoloChallengeBinding {
    return {
      userId: "user-alice",
      sessionId: SESSION_ID,
      runPolicyDigest: digestFor("policy"),
      runtimeAssignmentId: ASSIGNMENT_ID,
      runtimeAssignmentGeneration: 1,
      sandboxId: "sandbox-1",
      sandboxGeneration: 1,
      runtimePrincipalId: "principal-1",
      runtimeAuthorizationGeneration: 1,
      ...overrides,
    };
  }

  function mintInitialGrant(): { grantId: string; result: null } {
    seedGrant(db, {
      grantId: "grant-1",
      approvalId: "approval-1",
      manifestId: "m1",
      effectKey: "e1",
    });
    return { grantId: "grant-1", result: null };
  }

  it("issues, then atomically consumes with the initial grant exactly once", () => {
    seedRun(db);
    const store = createYoloChallengeStore(db, { randomBytes });
    const issued = store.issue({
      challengeId: "yc-1",
      userId: "user-alice",
      binding: binding(),
      nowMs: 1_000,
    });
    const outcome = store.consumeWithGrant(
      { challenge: issued.challenge, binding: binding(), nowMs: 2_000 },
      () => mintInitialGrant()
    );
    expect(outcome).toMatchObject({ outcome: "consumed", grantId: "grant-1" });
    expect(
      db.prepare("SELECT status, consumed_grant_id FROM yolo_challenges WHERE id='yc-1'").get()
    ).toEqual({ status: "consumed", consumed_grant_id: "grant-1" });

    // second consumption is rejected and mints nothing
    let minted = 0;
    const again = store.consumeWithGrant(
      { challenge: issued.challenge, binding: binding(), nowMs: 3_000 },
      () => {
        minted += 1;
        return { grantId: "grant-2", result: null };
      }
    );
    expect(again).toMatchObject({ outcome: "already-resolved", status: "consumed" });
    expect(minted).toBe(0);
  });

  it("rejects a challenge presented against a changed Sandbox boundary", () => {
    seedRun(db);
    const store = createYoloChallengeStore(db, { randomBytes });
    const issued = store.issue({
      challengeId: "yc-1",
      userId: "user-alice",
      binding: binding(),
      nowMs: 1_000,
    });
    const outcome = store.consumeWithGrant(
      { challenge: issued.challenge, binding: binding({ sandboxGeneration: 2 }), nowMs: 2_000 },
      () => mintInitialGrant()
    );
    expect(outcome).toEqual({ outcome: "boundary-mismatch" });
    expect(db.prepare("SELECT status FROM yolo_challenges WHERE id='yc-1'").get()).toEqual({
      status: "active",
    });
  });

  it("expires a stale challenge and refuses to consume it", () => {
    seedRun(db);
    const store = createYoloChallengeStore(db, { randomBytes });
    const issued = store.issue({
      challengeId: "yc-1",
      userId: "user-alice",
      binding: binding(),
      ttlMs: 30_000,
      nowMs: 1_000,
    });
    const outcome = store.consumeWithGrant(
      { challenge: issued.challenge, binding: binding(), nowMs: 1_000 + 30_001 },
      () => mintInitialGrant()
    );
    expect(outcome).toEqual({ outcome: "expired" });
    expect(db.prepare("SELECT status FROM yolo_challenges WHERE id='yc-1'").get()).toEqual({
      status: "expired",
    });
  });

  it("invalidates outstanding challenges when the boundary changes", () => {
    seedRun(db);
    const store = createYoloChallengeStore(db, { randomBytes });
    const issued = store.issue({
      challengeId: "yc-1",
      userId: "user-alice",
      binding: binding(),
      nowMs: 1_000,
    });
    const changed = store.invalidateForBoundaryChange({
      sessionId: SESSION_ID,
      currentBindingDigest: digestFor(
        "a-different-boundary-digest-value-000000000000000000000000000000"
      ),
      nowMs: 1_500,
    });
    expect(changed).toBe(1);
    const outcome = store.consumeWithGrant(
      { challenge: issued.challenge, binding: binding(), nowMs: 2_000 },
      () => mintInitialGrant()
    );
    expect(outcome).toMatchObject({ outcome: "already-resolved", status: "invalidated" });
  });

  it("enforces issuance rate limits per actor and session", () => {
    seedRun(db);
    const store = createYoloChallengeStore(db, { randomBytes });
    for (let i = 0; i < 3; i += 1) {
      store.issue({
        challengeId: `yc-${i}`,
        userId: "user-alice",
        binding: binding(),
        nowMs: 1_000,
      });
    }
    // active cap is 3
    expect(() =>
      store.issue({ challengeId: "yc-x", userId: "user-alice", binding: binding(), nowMs: 1_000 })
    ).toThrow(/active/);
  });
});
