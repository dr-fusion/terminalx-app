import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RuntimeLifecycleCommand, RuntimeReceipt } from "@/lib/runtime/contracts";
import {
  canonicalRuntimeJson,
  digestRuntimeCommandClaims,
} from "@/lib/runtime/runtime-command-canonical";
import {
  RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS,
  createRuntimeReceiptObservationIssuer,
} from "@/lib/runtime";
import type { RuntimeBinding } from "@/lib/team-sessions/contracts";
import {
  createSqliteRuntimeReceiptFollowJournal,
  type RuntimeReceiptFollowLease,
  type RuntimeReceiptFollowSettlementInput,
  type RuntimeReceiptFollowSettlementResult,
  type SettleVerifiedRuntimeReceiptInTransaction,
} from "@/lib/team-sessions/sqlite-runtime-receipt-follow-journal";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";

const NOW = 2_000_000_000_000;
const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ASSIGNMENT_ID = "44444444-4444-4444-8444-444444444444";
const SANDBOX_ID = "sandbox:follow-test";
const PRINCIPAL_ID = "runtime-principal:follow-test";
const COMMAND_ID = "55555555-5555-4555-8555-555555555555";
const RUN_ID = "66666666-6666-4666-8666-666666666666";
const ISSUER_KEY_ID = "runtime-observer:test-key";
const REQUIRED_ENFORCER_SET_DIGEST = "d".repeat(64);

const BINDING: RuntimeBinding = Object.freeze({
  teamId: TEAM_ID,
  projectId: PROJECT_ID,
  sessionId: SESSION_ID,
  runtimeAssignmentId: ASSIGNMENT_ID,
  runtimeAssignmentGeneration: 1,
  sandboxId: SANDBOX_ID,
  sandboxGeneration: 1,
  runtimePrincipalId: PRINCIPAL_ID,
});

describe("SQLite Runtime signed receipt follow journal", () => {
  let directory: string;
  let privateKeyFile: string;
  let publicKeyPem: string;
  let database: TeamSessionDatabase;
  let receiptSequence: number;
  let eventSequence: number;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-receipt-follow-"));
    const keys = generateKeyPairSync("ed25519");
    privateKeyFile = path.join(directory, "runtime-observation-key.pem");
    fs.writeFileSync(privateKeyFile, keys.privateKey.export({ format: "pem", type: "pkcs8" }), {
      mode: 0o600,
    });
    fs.chmodSync(privateKeyFile, 0o600);
    publicKeyPem = keys.publicKey.export({ format: "pem", type: "spki" }).toString();
    receiptSequence = 0;
    eventSequence = 0;

    database = openTeamSessionDatabase({ filename: ":memory:" });
    database.db.pragma("foreign_keys = OFF");
    seedExactRuntimeBinding();
    dropCommandInsertGuardsForIsolatedFixture();
    insertAwaitingLifecycleCommand(lifecycleCommand());
  });

  afterEach(() => {
    database.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function seedExactRuntimeBinding(): void {
    database.db
      .prepare(`INSERT INTO teams (id, name, created_at_ms) VALUES (?, 'Acme', ?)`)
      .run(TEAM_ID, NOW);
    database.db
      .prepare(
        `INSERT INTO projects (id, team_id, name, created_at_ms)
         VALUES (?, ?, 'Terminal X', ?)`
      )
      .run(PROJECT_ID, TEAM_ID, NOW);
    database.db
      .prepare(
        `INSERT INTO sessions
           (id, team_id, project_id, name, status, steering_policy,
            runtime_kind, isolation, tmux_name, created_at_ms)
         VALUES (?, ?, ?, 'Follow truth', 'active', 'shared',
                 'local-tmux', 'trusted-shared-host', 'follow-truth', ?)`
      )
      .run(SESSION_ID, TEAM_ID, PROJECT_ID, NOW);
    database.db
      .prepare(
        `INSERT INTO runtime_assignments
           (id, session_id, team_id, project_id, generation, runtime_kind,
            sandbox_id, sandbox_generation, runtime_principal_id,
            runtime_authorization_generation, status, created_at_ms, retired_at_ms)
         VALUES (?, ?, ?, ?, 1, 'local-tmux', ?, 1, ?, 1, 'ready', ?, NULL)`
      )
      .run(ASSIGNMENT_ID, SESSION_ID, TEAM_ID, PROJECT_ID, SANDBOX_ID, PRINCIPAL_ID, NOW);
    database.db
      .prepare(
        `INSERT INTO runtime_authorization_epochs
           (session_id, generation, runtime_assignment_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms,
            effect_enforcer_set_digest)
         VALUES (?, 1, ?, 1, ?, 1, ?, ?, ?)`
      )
      .run(SESSION_ID, ASSIGNMENT_ID, SANDBOX_ID, PRINCIPAL_ID, NOW, REQUIRED_ENFORCER_SET_DIGEST);
  }

  function dropCommandInsertGuardsForIsolatedFixture(): void {
    for (const trigger of [
      "runtime_run_commands_immutable_update",
      "runtime_run_commands_immutable_delete",
      "runtime_run_commands_json_scope_binding",
      "runtime_run_commands_source_event_binding",
      "runtime_run_commands_start_identity_binding",
      "runtime_run_commands_current_state",
      "runtime_run_commands_enforcer_set_binding",
    ]) {
      database.db.exec(`DROP TRIGGER IF EXISTS ${trigger}`);
    }
  }

  function lifecycleCommand(): RuntimeLifecycleCommand {
    const claims = {
      kind: "run.pause" as const,
      commandId: COMMAND_ID,
      binding: BINDING,
      projectCeilingRevision: "local-tmux-ceiling:v1",
      runtimeAuthorizationGeneration: 1,
      requiredEffectEnforcerSetDigest: REQUIRED_ENFORCER_SET_DIGEST,
      causationId: "event:pause-request",
      actor: { kind: "human" as const, actorRef: "alice" },
      issuedAtMs: NOW,
      deadlineAtMs: NOW + 60_000,
      agentRunId: RUN_ID,
      runPolicyRevision: 1,
      fromRunStateVersion: 1,
      toRunStateVersion: 2,
      reason: "human" as const,
    };
    return Object.freeze({
      ...claims,
      authority: {
        issuer: "team-session" as const,
        issuerKeyId: "team-session:test-key",
        audience: "runtime" as const,
        capability: "run.pause" as const,
        claimsDigest: digestRuntimeCommandClaims(claims),
        issuedAtMs: NOW,
        expiresAtMs: NOW + 60_000,
        signature: "A".repeat(86),
      },
    });
  }

  function insertAwaitingLifecycleCommand(command: RuntimeLifecycleCommand): void {
    const commandJson = JSON.stringify(command);
    const commandDigest = sha256(canonicalRuntimeJson(command));
    database.db
      .prepare(
        `INSERT INTO runtime_run_commands
           (id, session_id, agent_run_id, command_sequence, previous_command_sequence,
            operation, target_lifecycle, expected_run_state_version,
            target_run_state_version, run_policy_revision, goal_set_id,
            goal_set_revision, runtime_assignment_id, runtime_assignment_generation,
            sandbox_id, sandbox_generation, runtime_principal_id,
            runtime_authorization_generation, required_effect_enforcer_set_digest,
            source_session_sequence, command_json,
            command_digest, authority_digest, created_at_ms, deadline_at_ms)
         VALUES (?, ?, ?, 1, NULL, 'run.pause', 'paused', 1, 2, 1,
                 'goal-set:follow', 1, ?, 1, ?, 1, ?, 1, ?, 1, ?, ?, ?, ?, ?)`
      )
      .run(
        command.commandId,
        SESSION_ID,
        RUN_ID,
        ASSIGNMENT_ID,
        SANDBOX_ID,
        PRINCIPAL_ID,
        REQUIRED_ENFORCER_SET_DIGEST,
        commandJson,
        commandDigest,
        command.authority.claimsDigest,
        NOW,
        NOW + 60_000
      );
    database.db
      .prepare(
        `INSERT INTO runtime_run_command_dispatch
           (command_id, agent_run_id, status, attempts, available_at_ms,
            lease_owner, lease_expires_at_ms, last_safe_error_code,
            created_at_ms, updated_at_ms, terminal_at_ms)
         VALUES (?, ?, 'pending', 0, ?, NULL, NULL, NULL, ?, ?, NULL)`
      )
      .run(command.commandId, RUN_ID, NOW, NOW, NOW);
    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'processing', attempts = 1, lease_owner = 'dispatch-worker',
             lease_expires_at_ms = ?, updated_at_ms = ?
         WHERE command_id = ?`
      )
      .run(NOW + 1_000, NOW, command.commandId);
    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET dispatch_interlock_acquired_at_ms = updated_at_ms
         WHERE command_id = ?`
      )
      .run(command.commandId);
    database.db
      .prepare(
        `UPDATE runtime_run_command_dispatch
         SET status = 'awaiting-receipt', lease_owner = NULL,
             lease_expires_at_ms = NULL, last_safe_error_code = 'runtime_internal',
             updated_at_ms = ?
         WHERE command_id = ?`
      )
      .run(NOW, command.commandId);
  }

  function testSettlement(): SettleVerifiedRuntimeReceiptInTransaction {
    return (input) => persistAcceptedReceipt(input);
  }

  function persistAcceptedReceipt(
    input: RuntimeReceiptFollowSettlementInput
  ): RuntimeReceiptFollowSettlementResult {
    expect(database.db.inTransaction).toBe(true);
    const receipt = input.observation.receipt;
    if (receipt.outcome !== "accepted") throw new Error("Fixture only persists accepted receipts");
    const persisted: RuntimeReceipt = {
      commandId: receipt.commandId,
      binding: { ...receipt.binding },
      runtimeAuthorizationGeneration: receipt.runtimeAuthorizationGeneration,
      outcome: "accepted",
      effectRef: `effect:${sha256(receipt.effectRef)}`,
    };
    const receiptJson = JSON.stringify(persisted);
    const receiptDigest = sha256(canonicalRuntimeJson(persisted));
    const exact = database.db
      .prepare(
        `SELECT id FROM runtime_run_command_receipts
         WHERE command_id = ? AND receipt_digest = ?`
      )
      .get(input.command.commandId, receiptDigest) as { id: string } | undefined;
    if (exact) return Object.freeze({ receiptId: exact.id, effectiveReceiptDigest: receiptDigest });

    receiptSequence += 1;
    const receiptId = `receipt:follow:${receiptSequence}`;
    const row = database.db
      .prepare(`SELECT * FROM runtime_run_commands WHERE id = ?`)
      .get(input.command.commandId) as Record<string, string | number>;
    database.db
      .prepare(
        `INSERT INTO runtime_run_command_receipts
           (id, command_id, version, previous_version, session_id, agent_run_id,
            command_sequence, run_policy_revision, goal_set_id, goal_set_revision,
            runtime_assignment_id, runtime_assignment_generation, sandbox_id,
            sandbox_generation, runtime_principal_id, runtime_authorization_generation,
            expected_run_state_version, target_run_state_version, source_session_sequence,
            command_digest, outcome, original_outcome, original_receipt_digest,
            receipt_json, receipt_digest, received_at_ms)
         VALUES (?, ?, 1, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                 'accepted', NULL, NULL, ?, ?, ?)`
      )
      .run(
        receiptId,
        row.id,
        row.session_id,
        row.agent_run_id,
        row.command_sequence,
        row.run_policy_revision,
        row.goal_set_id,
        row.goal_set_revision,
        row.runtime_assignment_id,
        row.runtime_assignment_generation,
        row.sandbox_id,
        row.sandbox_generation,
        row.runtime_principal_id,
        row.runtime_authorization_generation,
        row.expected_run_state_version,
        row.target_run_state_version,
        row.source_session_sequence,
        row.command_digest,
        receiptJson,
        receiptDigest,
        input.receivedAtMs
      );
    return Object.freeze({ receiptId, effectiveReceiptDigest: receiptDigest });
  }

  function createJournal(
    settlement: SettleVerifiedRuntimeReceiptInTransaction = testSettlement(),
    retryDelayMs = 50
  ) {
    return createSqliteRuntimeReceiptFollowJournal({
      db: database.db,
      idGenerator: () => `event:follow:${++eventSequence}`,
      settleVerifiedReceiptInTransaction: settlement,
      retryDelayMs,
    });
  }

  function register(journal = createJournal()) {
    return journal.register({
      binding: BINDING,
      runtimeAuthorizationGeneration: 1,
      issuerKeyId: ISSUER_KEY_ID,
      publicKeySpkiPem: publicKeyPem,
      createdAtMs: NOW,
    });
  }

  function claim(journal: ReturnType<typeof createJournal>, nowMs = NOW, duration = 1_000) {
    const lease = journal.claim({ workerId: "follow-worker", leaseDurationMs: duration, nowMs });
    if (!lease) throw new Error("Expected receipt follow lease");
    return lease;
  }

  function exactLease(lease: RuntimeReceiptFollowLease, nowMs: number) {
    return {
      runtimeAssignmentId: lease.binding.runtimeAssignmentId,
      runtimeAuthorizationGeneration: lease.runtimeAuthorizationGeneration,
      workerId: lease.leaseOwner,
      expectedLeaseVersion: lease.leaseVersion,
      expectedLeaseExpiresAtMs: lease.leaseExpiresAtMs,
      nowMs,
    } as const;
  }

  function issuer(clock: () => number = () => NOW) {
    return createRuntimeReceiptObservationIssuer({
      issuerKeyId: ISSUER_KEY_ID,
      binding: BINDING,
      privateKeyFile,
      clock,
      observationTtlMs: 30_000,
    });
  }

  function acceptedReceipt(): RuntimeReceipt {
    return {
      commandId: COMMAND_ID,
      binding: BINDING,
      runtimeAuthorizationGeneration: 1,
      outcome: "accepted",
      effectRef: "provider-private-effect-reference",
    };
  }

  it("keeps awaiting rows unclaimable until an exact key and stream are registered", () => {
    const journal = createJournal();
    expect(
      journal.claim({ workerId: "follow-worker", leaseDurationMs: 1_000, nowMs: NOW })
    ).toBeNull();

    const registered = register(journal);
    const expectedDigest = sha256(generatePublicDer(publicKeyPem));
    expect(registered).toEqual({
      binding: BINDING,
      runtimeAuthorizationGeneration: 1,
      issuerKeyId: ISSUER_KEY_ID,
      publicKeySpkiDigest: expectedDigest,
    });
    expect(Object.isFrozen(registered.binding)).toBe(true);
    expect(claim(journal)).toMatchObject({
      binding: BINDING,
      runtimeAuthorizationGeneration: 1,
      issuerKeyId: ISSUER_KEY_ID,
      publicKeySpkiDigest: expectedDigest,
      checkpoint: null,
      attempt: 1,
      leaseVersion: 1,
    });
  });

  it("does not grant migrated v5 rows a trusted follow stream", () => {
    database.db.exec("DROP TRIGGER runtime_authorization_epochs_immutable_update");
    database.db
      .prepare(
        `UPDATE runtime_authorization_epochs SET effect_enforcer_set_digest = NULL
         WHERE session_id = ? AND generation = 1`
      )
      .run(SESSION_ID);
    database.db
      .prepare(
        `UPDATE runtime_run_commands SET required_effect_enforcer_set_digest = NULL
         WHERE id = ?`
      )
      .run(COMMAND_ID);
    const journal = createJournal();

    expect(() => register(journal)).toThrowError(
      expect.objectContaining({ code: "binding_unavailable" })
    );
    expect(
      journal.claim({ workerId: "follow-worker", leaseDurationMs: 1_000, nowMs: NOW })
    ).toBeNull();
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_receipt_follow_streams`).get()
    ).toEqual({ count: 0 });
  });

  it("rejects key substitution and non-Ed25519 trust roots without creating partial state", () => {
    const journal = createJournal();
    expect(() =>
      journal.register({
        binding: { ...BINDING, sandboxId: "sandbox:substitution" },
        runtimeAuthorizationGeneration: 1,
        issuerKeyId: ISSUER_KEY_ID,
        publicKeySpkiPem: publicKeyPem,
        createdAtMs: NOW,
      })
    ).toThrowError(expect.objectContaining({ code: "binding_unavailable" }));

    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({
      format: "pem",
      type: "spki",
    });
    expect(() =>
      journal.register({
        binding: BINDING,
        runtimeAuthorizationGeneration: 1,
        issuerKeyId: ISSUER_KEY_ID,
        publicKeySpkiPem: rsa.toString(),
        createdAtMs: NOW,
      })
    ).toThrowError(expect.objectContaining({ code: "invalid_public_key" }));
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_principal_observation_keys`).get()
    ).toEqual({ count: 0 });
  });

  it("renews, releases, and reconciles only exact one-at-a-time follow leases", () => {
    const journal = createJournal(testSettlement(), 50);
    register(journal);
    const first = claim(journal, NOW, 100);
    expect(() =>
      journal.renew({
        ...exactLease(first, NOW + 10),
        workerId: "other-worker",
        leaseDurationMs: 200,
      })
    ).toThrowError(expect.objectContaining({ code: "stale_lease" }));

    const renewed = journal.renew({
      ...exactLease(first, NOW + 10),
      leaseDurationMs: 200,
    });
    expect(renewed.leaseExpiresAtMs).toBe(NOW + 210);
    expect(() =>
      journal.release({ ...exactLease(first, NOW + 20), reason: "no-event" })
    ).toThrowError(expect.objectContaining({ code: "stale_lease" }));

    const current = { ...first, leaseExpiresAtMs: renewed.leaseExpiresAtMs };
    journal.release({ ...exactLease(current, NOW + 20), reason: "no-event" });
    expect(
      journal.claim({ workerId: "follow-worker", leaseDurationMs: 100, nowMs: NOW + 69 })
    ).toBeNull();
    const second = claim(journal, NOW + 70, 100);
    expect(second).toMatchObject({ attempt: 2, leaseVersion: 2 });
    expect(journal.reconcile(second.leaseExpiresAtMs - 1)).toBe(0);
    expect(journal.reconcile(second.leaseExpiresAtMs)).toBe(1);
    const third = claim(journal, second.leaseExpiresAtMs, 100);
    expect(third).toMatchObject({ attempt: 3, leaseVersion: 3 });
  });

  it("atomically verifies, persists, and advances one signed cursor under the exact lease", () => {
    const journal = createJournal();
    register(journal);
    const lease = claim(journal);
    const observation = issuer().issue({
      observationId: "observation:1",
      cursor: "cursor:1",
      previous: null,
      command: lifecycleCommand(),
      receipt: acceptedReceipt(),
    });

    const settled = journal.settle({
      ...exactLease(lease, NOW),
      observation,
      receivedAtMs: NOW,
    });
    expect(settled.receiptId).toBe("receipt:follow:1");
    expect(
      database.db
        .prepare(
          `SELECT stream.status, stream.cursor, stream.last_observation_digest,
                  stream.receipt_sequence, event.command_id, event.receipt_id,
                  event.wire_receipt_digest, event.effective_receipt_digest
           FROM runtime_receipt_follow_streams stream
           JOIN runtime_receipt_follow_events event
             ON event.runtime_assignment_id = stream.runtime_assignment_id
            AND event.runtime_authorization_generation = stream.runtime_authorization_generation`
        )
        .get()
    ).toMatchObject({
      status: "pending",
      cursor: "cursor:1",
      receipt_sequence: 1,
      command_id: COMMAND_ID,
      receipt_id: "receipt:follow:1",
      effective_receipt_digest: settled.effectiveReceiptDigest,
    });
    expect(
      database.db
        .prepare(`SELECT status FROM runtime_run_command_dispatch WHERE command_id = ?`)
        .get(COMMAND_ID)
    ).toEqual({ status: "awaiting-receipt" });
    expect(() =>
      journal.settle({ ...exactLease(lease, NOW), observation, receivedAtMs: NOW })
    ).toThrowError(expect.objectContaining({ code: "stale_lease" }));
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_receipt_follow_events`).get()
    ).toEqual({ count: 1 });
  });

  it("settles the shared maximum cursor and the SQLite schema rejects max plus one", () => {
    const journal = createJournal();
    register(journal);
    const lease = claim(journal);
    const maximumCursor = "🧭".repeat(RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS);
    const observation = issuer().issue({
      observationId: "observation:maximum-cursor",
      cursor: maximumCursor,
      previous: null,
      command: lifecycleCommand(),
      receipt: acceptedReceipt(),
    });

    journal.settle({ ...exactLease(lease, NOW), observation, receivedAtMs: NOW });
    expect(database.db.prepare(`SELECT cursor FROM runtime_receipt_follow_streams`).get()).toEqual({
      cursor: maximumCursor,
    });

    database.db.exec("DROP TRIGGER runtime_receipt_follow_streams_valid_transition");
    expect(() =>
      database.db
        .prepare(`UPDATE runtime_receipt_follow_streams SET cursor = ?`)
        .run(`${maximumCursor}🧭`)
    ).toThrow(/CHECK constraint failed/);
    expect(database.db.prepare(`SELECT cursor FROM runtime_receipt_follow_streams`).get()).toEqual({
      cursor: maximumCursor,
    });
  });

  it("quarantines a max-plus-one cursor before invoking lifecycle settlement", () => {
    let settlementInvoked = false;
    const journal = createJournal((input) => {
      settlementInvoked = true;
      return persistAcceptedReceipt(input);
    });
    register(journal);
    const lease = claim(journal);
    const maximumCursor = "🧭".repeat(RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS);
    const valid = issuer().issue({
      observationId: "observation:overbound-cursor",
      cursor: maximumCursor,
      previous: null,
      command: lifecycleCommand(),
      receipt: acceptedReceipt(),
    });
    const overbound = { ...valid, cursor: `${maximumCursor}🧭` };

    expect(() =>
      journal.settle({ ...exactLease(lease, NOW), observation: overbound, receivedAtMs: NOW })
    ).toThrowError(expect.objectContaining({ code: "invalid_observation" }));
    expect(settlementInvoked).toBe(false);
    expect(
      database.db
        .prepare(`SELECT status, cursor, last_safe_error_code FROM runtime_receipt_follow_streams`)
        .get()
    ).toEqual({ status: "quarantined", cursor: null, last_safe_error_code: "invalid_observation" });
  });

  it("quarantines a validly signed fork instead of advancing the durable chain", () => {
    const journal = createJournal();
    register(journal);
    const firstLease = claim(journal);
    const first = issuer().issue({
      observationId: "observation:1",
      cursor: "cursor:1",
      previous: null,
      command: lifecycleCommand(),
      receipt: acceptedReceipt(),
    });
    journal.settle({ ...exactLease(firstLease, NOW), observation: first, receivedAtMs: NOW });

    const secondNow = NOW + 50;
    const secondLease = claim(journal, secondNow);
    const fork = issuer(() => secondNow).issue({
      observationId: "observation:fork",
      cursor: "cursor:fork",
      previous: null,
      command: lifecycleCommand(),
      receipt: acceptedReceipt(),
    });
    expect(() =>
      journal.settle({
        ...exactLease(secondLease, secondNow),
        observation: fork,
        receivedAtMs: secondNow,
      })
    ).toThrowError(expect.objectContaining({ code: "invalid_observation" }));
    expect(
      database.db
        .prepare(
          `SELECT status, cursor, receipt_sequence, last_safe_error_code
           FROM runtime_receipt_follow_streams`
        )
        .get()
    ).toEqual({
      status: "quarantined",
      cursor: "cursor:1",
      receipt_sequence: 1,
      last_safe_error_code: "invalid_observation_chain",
    });
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_receipt_follow_events`).get()
    ).toEqual({ count: 1 });
  });

  it("rolls receipt writes back when the lifecycle settlement seam fails", () => {
    const journal = createJournal((input) => {
      persistAcceptedReceipt(input);
      throw new Error("simulated lifecycle conflict");
    });
    register(journal);
    const lease = claim(journal);
    const observation = issuer().issue({
      observationId: "observation:rollback",
      cursor: "cursor:rollback",
      previous: null,
      command: lifecycleCommand(),
      receipt: acceptedReceipt(),
    });
    expect(() =>
      journal.settle({ ...exactLease(lease, NOW), observation, receivedAtMs: NOW })
    ).toThrowError(expect.objectContaining({ code: "journal_conflict" }));
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_run_command_receipts`).get()
    ).toEqual({ count: 0 });
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_receipt_follow_events`).get()
    ).toEqual({ count: 0 });
    expect(
      database.db.prepare(`SELECT status, cursor FROM runtime_receipt_follow_streams`).get()
    ).toEqual({ status: "processing", cursor: null });
  });

  it("does not invoke hostile observation getters and contains the stream", () => {
    const journal = createJournal();
    register(journal);
    const lease = claim(journal);
    let invoked = false;
    const hostile = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(hostile, "command", {
      enumerable: true,
      get() {
        invoked = true;
        return { commandId: COMMAND_ID };
      },
    });
    expect(() =>
      journal.settle({ ...exactLease(lease, NOW), observation: hostile, receivedAtMs: NOW })
    ).toThrowError(expect.objectContaining({ code: "invalid_observation" }));
    expect(invoked).toBe(false);
    expect(
      database.db
        .prepare(`SELECT status, last_safe_error_code FROM runtime_receipt_follow_streams`)
        .get()
    ).toEqual({ status: "quarantined", last_safe_error_code: "invalid_observation" });
  });
});

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function generatePublicDer(pem: string): Buffer {
  return createPublicKey(pem).export({ format: "der", type: "spki" });
}
