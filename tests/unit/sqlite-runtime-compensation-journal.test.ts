import { createHash, generateKeyPairSync } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AggregateEnforcementProof,
  NonDuplicateRuntimeCompensationReceipt,
  RuntimeCompensationCommand,
  RuntimeCompensationReceipt,
} from "@/lib/runtime/contracts";
import { digestRuntimeCommandClaims } from "@/lib/runtime/runtime-command-canonical";
import { digestRuntimeCompensationEnforcementSubject } from "@/lib/runtime/runtime-compensation-enforcement-proof";
import { digestNonDuplicateRuntimeCompensationReceipt } from "@/lib/runtime/runtime-compensation-execution";
import {
  digestRuntimeCompensationIncident,
  type RuntimeCompensationIncident,
} from "@/lib/runtime/runtime-compensation-incident";
import type {
  RuntimeCompensationCommandAuthorityVerifier,
  RuntimeCompensationMaterializationCandidate,
} from "@/lib/runtime/runtime-compensation-materializer";
import {
  createRuntimeCompensationReceiptObservationIssuer,
  createRuntimeCompensationReceiptObservationVerifier,
  type VerifiedRuntimeCompensationReceiptObservation,
} from "@/lib/runtime/runtime-compensation-receipt-observation";
import {
  commitRuntimeEffectRef,
  digestAggregateEnforcementProof,
  snapshotPersistedRuntimeEffectRefCommitment,
} from "@/lib/runtime/runtime-enforcement-proof";
import {
  createSqliteRuntimeCompensationJournal,
  RuntimeCompensationJournalError,
  RuntimeCompensationReceiptFollowSettlementRejection,
  type SqliteRuntimeCompensationJournal,
} from "@/lib/team-sessions/sqlite-runtime-compensation-journal";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ASSIGNMENT_ID = "44444444-4444-4444-8444-444444444444";
const SOURCE_COMMAND_ID = "runtime-command-1";
const SOURCE_RECEIPT_ID = "source-receipt-1";
const COMPENSATION_ID = "compensation-1";
const COMPENSATION_COMMAND_ID = "compensation-command-1";
const SOURCE_ENFORCER_SET_DIGEST = "e".repeat(64);
const SOURCE_SUBJECT_DIGEST = "f".repeat(64);
const SOURCE_PROOF_DIGEST = "a".repeat(64);
const CONTAINMENT_ENFORCER_SET_DIGEST = "c".repeat(64);
const RAW_EFFECT_REF = "provider-secret-effect-reference";
const PLATFORM_SIGNATURE = "A".repeat(86);
const OBSERVATION_ISSUER_KEY_ID = "daytona-compensation-observer:v1";

describe("SQLite Runtime compensation journal", () => {
  let directory: string;
  let filename: string;
  let observationPrivateKeyFile: string;
  let observationPublicKeyPem: string;
  let database: TeamSessionDatabase | undefined;
  let nextId: number;
  let nextObservation: number;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-compensation-journal-"));
    filename = path.join(directory, "team-sessions.sqlite");
    const keyPair = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    observationPrivateKeyFile = path.join(directory, "compensation-observer-private.pem");
    observationPublicKeyPem = keyPair.publicKey;
    fs.writeFileSync(observationPrivateKeyFile, keyPair.privateKey, { mode: 0o600 });
    database = openTeamSessionDatabase({ filename });
    seedVerifiedCompensationIncident(database.db);
    nextId = 0;
    nextObservation = 0;
  });

  afterEach(() => {
    database?.close();
    database = undefined;
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function journal(
    options: {
      authority?: RuntimeCompensationCommandAuthorityVerifier;
      proof?: () => boolean;
      retryDelayMs?: number;
    } = {}
  ): SqliteRuntimeCompensationJournal {
    return createSqliteRuntimeCompensationJournal({
      db: database!.db,
      idGenerator: () => `compensation-journal-id-${++nextId}`,
      verifyAuthority:
        options.authority ?? (({ command }) => command.authority.signature === PLATFORM_SIGNATURE),
      verifyEnforcementProof: options.proof ?? (() => true),
      retryDelayMs: options.retryDelayMs,
    });
  }

  function verifiedObservation(
    command: RuntimeCompensationCommand,
    receipt: RuntimeCompensationReceipt,
    observedAtMs = 150
  ): VerifiedRuntimeCompensationReceiptObservation {
    const sequence = ++nextObservation;
    const observation = createRuntimeCompensationReceiptObservationIssuer({
      issuerKeyId: OBSERVATION_ISSUER_KEY_ID,
      binding: command.binding,
      privateKeyFile: observationPrivateKeyFile,
      clock: () => observedAtMs,
      observationTtlMs: 100,
    }).issue({
      observationId: `compensation-observation-${sequence}`,
      cursor: `compensation-cursor-${sequence}`,
      previous: null,
      command,
      receipt,
    });
    return createRuntimeCompensationReceiptObservationVerifier({
      pinnedPublicKeys: [
        {
          issuerKeyId: OBSERVATION_ISSUER_KEY_ID,
          binding: command.binding,
          publicKeyPem: observationPublicKeyPem,
        },
      ],
      maximumObservationTtlMs: 100,
    }).verify({ observation, command, expectedPrevious: null, nowMs: observedAtMs });
  }

  function settleLateReceipt(
    active: SqliteRuntimeCompensationJournal,
    command: RuntimeCompensationCommand,
    observation: VerifiedRuntimeCompensationReceiptObservation,
    receivedAtMs = observation.observedAtMs + 1
  ) {
    return database!.db
      .transaction(() =>
        active.settleVerifiedReceiptInTransaction({
          observation,
          command,
          receivedAtMs,
          actorRef: "compensation-follow-worker",
        })
      )
      .immediate();
  }

  async function parkAwaitingReceipt(active: SqliteRuntimeCompensationJournal) {
    const { command } = await materializeCommand(active);
    const lease = await claimAndInterlock(active);
    const receipt = acceptedReceipt(command);
    await active.complete({
      ...leaseCompletion(lease, 140),
      outcome: { kind: "receipt", receipt },
    });
    return { command, receipt };
  }

  it("materializes one exact signed command idempotently and survives journal restart", async () => {
    const verifyAuthority = vi.fn<RuntimeCompensationCommandAuthorityVerifier>(
      ({ command }) => command.authority.signature === PLATFORM_SIGNATURE
    );
    const firstJournal = journal({ authority: verifyAuthority });
    const { candidate, command } = await materializeCommand(firstJournal);

    expect(await firstJournal.findMaterializable({ nowMs: 124 })).toBeNull();
    expect(
      await firstJournal.materialize({
        compensationId: candidate.compensationId,
        incidentDigest: candidate.incidentDigest,
        command,
        authorityVerifiedAtMs: 121,
        materializedAtMs: 123,
      })
    ).toBe("already-materialized");
    expect(verifyAuthority).toHaveBeenCalledWith({ command, nowMs: 121 });
    expect(verifyAuthority).toHaveBeenCalledWith({ command, nowMs: 123 });

    database!.close();
    database = openTeamSessionDatabase({ filename });
    const restarted = journal();
    const persisted = database.db
      .prepare(
        `SELECT command.authority_verified_at_ms, dispatch.status,
                dispatch.available_at_ms, dispatch.created_at_ms
         FROM runtime_compensation_commands command
         JOIN runtime_compensation_dispatch dispatch
           ON dispatch.compensation_command_id = command.id`
      )
      .get();
    expect(persisted).toEqual({
      authority_verified_at_ms: 123,
      status: "pending",
      available_at_ms: 123,
      created_at_ms: 123,
    });
    expect(await restarted.findMaterializable({ nowMs: 124 })).toBeNull();
    expect(
      database.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_commands`).get()
    ).toEqual({ count: 1 });
  });

  it("fails closed when pinned authority verification rejects at materialization", async () => {
    const rejected = journal({ authority: () => false });
    const candidate = await requiredCandidate(rejected);
    const command = compensationCommand(candidate);

    await expect(
      rejected.materialize({
        compensationId: candidate.compensationId,
        incidentDigest: candidate.incidentDigest,
        command,
        authorityVerifiedAtMs: 121,
        materializedAtMs: 123,
      })
    ).rejects.toMatchObject({ code: "invalid_command" });
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_commands`).get()
    ).toEqual({ count: 0 });
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_dispatch`).get()
    ).toEqual({ count: 0 });
  });

  it("reclaims only a pre-interlock stale lease and preserves its attempt sequence", async () => {
    const firstJournal = journal({ retryDelayMs: 10 });
    await materializeCommand(firstJournal);
    const first = await firstJournal.claim({
      workerId: "worker-a",
      leaseDurationMs: 20,
      nowMs: 130,
    });
    expect(first).toMatchObject({ attempt: 1, leaseOwner: "worker-a", leaseExpiresAtMs: 150 });
    expect(
      await firstJournal.claim({ workerId: "worker-b", leaseDurationMs: 20, nowMs: 131 })
    ).toBeNull();

    const restarted = journal({ retryDelayMs: 10 });
    await restarted.reconcile({ nowMs: 151 });
    expect(
      await restarted.claim({ workerId: "worker-b", leaseDurationMs: 20, nowMs: 160 })
    ).toBeNull();
    const second = await restarted.claim({
      workerId: "worker-b",
      leaseDurationMs: 20,
      nowMs: 161,
    });
    expect(second).toMatchObject({ attempt: 2, leaseOwner: "worker-b", leaseExpiresAtMs: 181 });
  });

  it("parks accepted work durably and never re-dispatches it", async () => {
    const active = journal();
    const { command } = await materializeCommand(active);
    const lease = await claimAndInterlock(active);
    const receipt: RuntimeCompensationReceipt = {
      ...receiptBase(command),
      outcome: "accepted",
      effectRef: RAW_EFFECT_REF,
    };

    await active.complete({
      ...leaseCompletion(lease, 140),
      outcome: { kind: "receipt", receipt },
    });
    const persisted = database!.db
      .prepare(
        `SELECT dispatch.status, dispatch.lease_owner, receipt.effect_ref_commitment,
                receipt.receipt_json
         FROM runtime_compensation_dispatch dispatch
         JOIN runtime_compensation_receipts receipt
           ON receipt.compensation_command_id = dispatch.compensation_command_id`
      )
      .get() as Record<string, string | null>;
    expect(persisted.status).toBe("awaiting-receipt");
    expect(persisted.lease_owner).toBeNull();
    expect(persisted.effect_ref_commitment).toBe(commitRuntimeEffectRef(RAW_EFFECT_REF));
    expect(persisted.receipt_json).not.toContain(RAW_EFFECT_REF);
    await active.reconcile({ nowMs: 10_000 });
    expect(
      await active.claim({ workerId: "worker-b", leaseDurationMs: 100, nowMs: 10_001 })
    ).toBeNull();
  });

  it("lets the durable interlock dominate a later not-dispatched failure", async () => {
    const active = journal();
    await materializeCommand(active);
    const lease = await claimAndInterlock(active);

    await active.complete({
      ...leaseCompletion(lease, 140),
      outcome: {
        kind: "failure",
        code: "invalid_authority",
        dispatchCertainty: "not-dispatched",
      },
    });
    expect(dispatchState(database!.db)).toMatchObject({
      status: "awaiting-receipt",
      lease_owner: null,
      last_safe_error_code: "invalid_authority",
    });
    await active.reconcile({ nowMs: 1_000 });
    expect(
      await active.claim({ workerId: "worker-b", leaseDurationMs: 100, nowMs: 1_001 })
    ).toBeNull();
  });

  it("atomically proves and applies containment, redacts provider data, and is idempotent", async () => {
    const verifyProof = vi.fn(() => true);
    const active = journal({ proof: verifyProof });
    const { command } = await materializeCommand(active);
    const lease = await claimAndInterlock(active);
    const receipt = enforcedReceipt(command, command.safetyFence);
    const completion = {
      ...leaseCompletion(lease, 140),
      outcome: { kind: "receipt" as const, receipt },
    };

    await active.complete(completion);
    await active.complete(completion);

    expect(verifyProof).toHaveBeenCalled();
    expect(dispatchState(database!.db)).toMatchObject({ status: "enforced" });
    expect(
      database!.db
        .prepare(
          `SELECT status, last_safe_error_code FROM runtime_run_command_dispatch
           WHERE command_id = ?`
        )
        .get(SOURCE_COMMAND_ID)
    ).toEqual({
      status: "quarantined",
      last_safe_error_code: "stale_enforced_effect_compensated",
    });
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_effects`).get()
    ).toEqual({ count: 1 });
    expect(
      database!.db
        .prepare(
          `SELECT COUNT(*) AS count FROM session_events
           WHERE type = 'run.runtime-command.compensated'`
        )
        .get()
    ).toEqual({ count: 1 });
    const stored = database!.db
      .prepare(
        `SELECT effect_ref_commitment, receipt_json, proof_verified_at_ms,
                enforced_safety_fence
         FROM runtime_compensation_receipts`
      )
      .get() as Record<string, string | number>;
    expect(stored.effect_ref_commitment).toBe(commitRuntimeEffectRef(RAW_EFFECT_REF));
    expect(stored.receipt_json).not.toContain(RAW_EFFECT_REF);
    expect(stored.proof_verified_at_ms).toBe(140);
    expect(stored.enforced_safety_fence).toBe(command.safetyFence);
    expect(database!.db.pragma("foreign_key_check")).toEqual([]);
  });

  it("rolls back every settlement write when containment proof verification fails", async () => {
    const active = journal({ proof: () => false });
    const { command } = await materializeCommand(active);
    const lease = await claimAndInterlock(active);

    await expect(
      active.complete({
        ...leaseCompletion(lease, 140),
        outcome: {
          kind: "receipt",
          receipt: enforcedReceipt(command, command.safetyFence),
        },
      })
    ).rejects.toMatchObject({ code: "invalid_input" });
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_receipts`).get()
    ).toEqual({ count: 0 });
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_effects`).get()
    ).toEqual({ count: 0 });
    expect(dispatchState(database!.db)).toMatchObject({ status: "processing" });
  });

  it("rejects an enforced fence below a newer durable high-water without partial writes", async () => {
    const active = journal();
    const { command } = await materializeCommand(active);
    const lease = await claimAndInterlock(active);
    database!.db
      .prepare(
        `UPDATE runtime_binding_safety_fences
         SET allocated_fence = 4, updated_at_ms = 135
         WHERE runtime_assignment_id = ?`
      )
      .run(ASSIGNMENT_ID);

    await expect(
      active.complete({
        ...leaseCompletion(lease, 140),
        outcome: {
          kind: "receipt",
          receipt: enforcedReceipt(command, command.safetyFence),
        },
      })
    ).rejects.toBeInstanceOf(RuntimeCompensationJournalError);
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_receipts`).get()
    ).toEqual({ count: 0 });
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM session_events WHERE sequence > 1`).get()
    ).toEqual({ count: 0 });

    const stronger = enforcedReceipt(command, 5);
    await active.complete({
      ...leaseCompletion(lease, 141),
      outcome: { kind: "receipt", receipt: stronger },
    });
    expect(
      database!.db
        .prepare(
          `SELECT allocated_fence FROM runtime_binding_safety_fences
           WHERE runtime_assignment_id = ?`
        )
        .get(ASSIGNMENT_ID)
    ).toEqual({ allocated_fence: 5 });
  });

  it.each(["rejected", "quarantined"] as const)(
    "blocks the source for a terminal %s receipt without persisting provider text",
    async (outcome) => {
      const active = journal();
      const { command } = await materializeCommand(active);
      const lease = await claimAndInterlock(active);
      const receipt: RuntimeCompensationReceipt =
        outcome === "rejected"
          ? {
              ...receiptBase(command),
              outcome,
              code: "forbidden",
              safeDetail: "provider controlled detail must disappear",
            }
          : {
              ...receiptBase(command),
              outcome,
              reason: "isolation_failure",
              effectRef: RAW_EFFECT_REF,
            };

      await active.complete({
        ...leaseCompletion(lease, 140),
        outcome: { kind: "receipt", receipt },
      });
      const stored = database!.db
        .prepare(
          `SELECT dispatch.status, dispatch.last_safe_error_code, receipt.receipt_json
           FROM runtime_compensation_dispatch dispatch
           JOIN runtime_compensation_receipts receipt
             ON receipt.compensation_command_id = dispatch.compensation_command_id`
        )
        .get() as Record<string, string>;
      expect(stored.status).toBe("blocked");
      expect(stored.last_safe_error_code).toBe(`compensation_${outcome}`);
      expect(stored.receipt_json).not.toContain("provider controlled detail");
      expect(stored.receipt_json).not.toContain(RAW_EFFECT_REF);
      expect(
        database!.db
          .prepare(`SELECT status FROM runtime_run_command_dispatch WHERE command_id = ?`)
          .get(SOURCE_COMMAND_ID)
      ).toEqual({ status: "compensating" });
    }
  );

  it("settles a branded late accepted duplicate exactly once and returns its stored digest", async () => {
    const active = journal();
    const { command, receipt: accepted } = await parkAwaitingReceipt(active);
    const duplicate: RuntimeCompensationReceipt = {
      ...receiptBase(command),
      outcome: "duplicate",
      originalReceipt: accepted,
      originalReceiptDigest: digestNonDuplicateRuntimeCompensationReceipt(accepted),
    };
    const observation = verifiedObservation(command, duplicate);

    const first = settleLateReceipt(active, command, observation);
    const second = settleLateReceipt(active, command, observation);

    expect(second).toEqual(first);
    expect(dispatchState(database!.db)).toMatchObject({ status: "awaiting-receipt" });
    expect(
      database!.db
        .prepare(
          `SELECT id, receipt_digest FROM runtime_compensation_receipts
           WHERE id = ?`
        )
        .get(first.receiptId)
    ).toEqual({ id: first.receiptId, receipt_digest: first.effectiveReceiptDigest });
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_receipts`).get()
    ).toEqual({ count: 2 });
  });

  it("atomically settles a branded late enforced receipt against the durable command", async () => {
    const verifyAuthority = vi.fn<RuntimeCompensationCommandAuthorityVerifier>(
      ({ command }) => command.authority.signature === PLATFORM_SIGNATURE
    );
    const active = journal({ authority: verifyAuthority });
    const { command } = await parkAwaitingReceipt(active);
    const observation = verifiedObservation(command, enforcedReceipt(command, command.safetyFence));

    const result = settleLateReceipt(active, command, observation);

    expect(result.effectiveReceiptDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(dispatchState(database!.db)).toMatchObject({ status: "enforced" });
    expect(
      database!.db
        .prepare(
          `SELECT receipt.receipt_digest, receipt.proof_verified_at_ms,
                  effect.receipt_id, event.actor_user_id
           FROM runtime_compensation_receipts receipt
           JOIN runtime_compensation_effects effect ON effect.receipt_id = receipt.id
           JOIN session_events event
             ON event.session_id = effect.session_id
            AND event.sequence = effect.applied_session_sequence`
        )
        .get()
    ).toEqual({
      receipt_digest: result.effectiveReceiptDigest,
      proof_verified_at_ms: 151,
      receipt_id: result.receiptId,
      actor_user_id: "compensation-follow-worker",
    });
    expect(
      database!.db
        .prepare(`SELECT status FROM runtime_run_command_dispatch WHERE command_id = ?`)
        .get(SOURCE_COMMAND_ID)
    ).toEqual({ status: "quarantined" });
    expect(verifyAuthority).toHaveBeenLastCalledWith({ command, nowMs: 123 });
  });

  it.each(["rejected", "quarantined"] as const)(
    "settles a branded late %s receipt by durably blocking compensation",
    async (outcome) => {
      const active = journal();
      const { command } = await parkAwaitingReceipt(active);
      const receipt: RuntimeCompensationReceipt =
        outcome === "rejected"
          ? {
              ...receiptBase(command),
              outcome,
              code: "forbidden",
              safeDetail: "provider text",
            }
          : {
              ...receiptBase(command),
              outcome,
              reason: "isolation_failure",
              effectRef: RAW_EFFECT_REF,
            };

      const result = settleLateReceipt(active, command, verifiedObservation(command, receipt));

      expect(result.effectiveReceiptDigest).toMatch(/^[0-9a-f]{64}$/);
      expect(dispatchState(database!.db)).toMatchObject({
        status: "blocked",
        last_safe_error_code: `compensation_${outcome}`,
      });
      expect(
        database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_effects`).get()
      ).toEqual({ count: 0 });
    }
  );

  it.each([
    ["false", (): boolean => false],
    [
      "throw",
      (): never => {
        throw new Error("provider verifier detail");
      },
    ],
    ["Promise", (): Promise<boolean> => Promise.resolve(true)],
  ] as const)(
    "fails closed and rolls back a branded late enforced receipt when proof verification returns %s",
    async (_behavior, unsafeProof) => {
      const active = journal({ proof: unsafeProof as unknown as () => boolean });
      const { command } = await parkAwaitingReceipt(active);
      const observation = verifiedObservation(
        command,
        enforcedReceipt(command, command.safetyFence)
      );

      expect(() => settleLateReceipt(active, command, observation)).toThrow(
        expect.objectContaining({
          name: "RuntimeCompensationReceiptFollowSettlementRejection",
          code: "enforcement_proof_verification_failed",
        })
      );
      expect(
        database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_receipts`).get()
      ).toEqual({ count: 1 });
      expect(
        database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_effects`).get()
      ).toEqual({ count: 0 });
      expect(dispatchState(database!.db)).toMatchObject({ status: "awaiting-receipt" });
    }
  );

  it("rejects a signed but unbranded late observation without changing durable state", async () => {
    const active = journal();
    const { command, receipt } = await parkAwaitingReceipt(active);
    const verified = verifiedObservation(command, receipt);
    const unbranded = Object.freeze({
      ...verified,
    }) as unknown as VerifiedRuntimeCompensationReceiptObservation;

    expect(() => settleLateReceipt(active, command, unbranded)).toThrow(
      expect.objectContaining({ name: "RuntimeCompensationJournalError", code: "invalid_input" })
    );
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_receipts`).get()
    ).toEqual({ count: 1 });
    expect(dispatchState(database!.db)).toMatchObject({ status: "awaiting-receipt" });
  });

  it("requires the caller's active transaction for branded late settlement", async () => {
    const active = journal();
    const { command, receipt } = await parkAwaitingReceipt(active);
    const observation = verifiedObservation(command, receipt);

    expect(() =>
      active.settleVerifiedReceiptInTransaction({
        observation,
        command,
        receivedAtMs: 151,
        actorRef: "compensation-follow-worker",
      })
    ).toThrow(expect.objectContaining({ code: "journal_conflict" }));
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_receipts`).get()
    ).toEqual({ count: 1 });
  });

  it("rejects a late enforced fence below durable high-water before every settlement write", async () => {
    const active = journal();
    const { command } = await parkAwaitingReceipt(active);
    database!.db
      .prepare(
        `UPDATE runtime_binding_safety_fences
         SET allocated_fence = 4, updated_at_ms = 145
         WHERE runtime_assignment_id = ?`
      )
      .run(ASSIGNMENT_ID);
    const staleObservation = verifiedObservation(
      command,
      enforcedReceipt(command, command.safetyFence)
    );

    expect(() => settleLateReceipt(active, command, staleObservation)).toThrow(
      RuntimeCompensationReceiptFollowSettlementRejection
    );
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_receipts`).get()
    ).toEqual({ count: 1 });
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM runtime_compensation_effects`).get()
    ).toEqual({ count: 0 });
    expect(
      database!.db.prepare(`SELECT COUNT(*) AS count FROM session_events WHERE sequence > 1`).get()
    ).toEqual({ count: 0 });
    expect(
      database!.db
        .prepare(
          `SELECT allocated_fence FROM runtime_binding_safety_fences
           WHERE runtime_assignment_id = ?`
        )
        .get(ASSIGNMENT_ID)
    ).toEqual({ allocated_fence: 4 });
    expect(dispatchState(database!.db)).toMatchObject({ status: "awaiting-receipt" });

    const strongerObservation = verifiedObservation(command, enforcedReceipt(command, 5), 152);
    settleLateReceipt(active, command, strongerObservation, 153);
    expect(
      database!.db
        .prepare(
          `SELECT allocated_fence FROM runtime_binding_safety_fences
           WHERE runtime_assignment_id = ?`
        )
        .get(ASSIGNMENT_ID)
    ).toEqual({ allocated_fence: 5 });
  });

  async function materializeCommand(active: SqliteRuntimeCompensationJournal) {
    const candidate = await requiredCandidate(active);
    const command = compensationCommand(candidate);
    expect(
      await active.materialize({
        compensationId: candidate.compensationId,
        incidentDigest: candidate.incidentDigest,
        command,
        authorityVerifiedAtMs: 121,
        materializedAtMs: 123,
      })
    ).toBe("created");
    return { candidate, command };
  }

  async function claimAndInterlock(active: SqliteRuntimeCompensationJournal) {
    const claimed = await active.claim({ workerId: "worker-a", leaseDurationMs: 100, nowMs: 130 });
    if (!claimed) throw new Error("Expected compensation delivery");
    const renewed = await active.renew({
      commandId: claimed.command.commandId,
      workerId: claimed.leaseOwner,
      expectedAttempt: claimed.attempt,
      expectedLeaseExpiresAtMs: claimed.leaseExpiresAtMs,
      leaseDurationMs: 100,
      nowMs: 131,
    });
    if (renewed.kind !== "renewed") throw new Error("Expected compensation interlock");
    return { ...claimed, leaseExpiresAtMs: renewed.leaseExpiresAtMs };
  }
});

async function requiredCandidate(
  journal: SqliteRuntimeCompensationJournal
): Promise<RuntimeCompensationMaterializationCandidate> {
  const candidate = await journal.findMaterializable({ nowMs: 115 });
  if (!candidate) throw new Error("Expected verified compensation incident");
  return candidate;
}

function compensationCommand(
  candidate: RuntimeCompensationMaterializationCandidate
): RuntimeCompensationCommand {
  const claims = {
    kind: "safety.quarantine" as const,
    commandId: COMPENSATION_COMMAND_ID,
    compensationId: candidate.compensationId,
    binding: candidate.binding,
    observedRuntimeAuthorizationGeneration: candidate.observedRuntimeAuthorizationGeneration,
    source: candidate.source,
    platformSecurityPolicyRevision: "platform-security-policy-1",
    requiredContainmentEnforcerSetDigest: CONTAINMENT_ENFORCER_SET_DIGEST,
    containment: {
      revokeTerminalWrites: true as const,
      stopProcessExecution: true as const,
      quarantineRuntime: true as const,
    },
    safetyFence: candidate.safetyFence,
    exactBindingOnly: true as const,
    advanceBeyondCurrentFences: true as const,
    reasonRef: candidate.incidentDigest,
    causationId: candidate.source.lifecycleCommandId,
    actor: { kind: "system" as const, actorRef: "platform-security" as const },
    issuedAtMs: 120,
    deadlineAtMs: 900,
  };
  return {
    ...claims,
    authority: {
      issuer: "platform-security",
      issuerKeyId: "platform-security-key-1",
      audience: "runtime",
      capability: "safety.quarantine",
      claimsDigest: digestRuntimeCommandClaims(claims),
      issuedAtMs: 120,
      expiresAtMs: 900,
      signature: PLATFORM_SIGNATURE,
    },
  };
}

function receiptBase(command: RuntimeCompensationCommand) {
  return {
    receiptKind: "runtime.compensation" as const,
    compensationId: command.compensationId,
    commandId: command.commandId,
    binding: command.binding,
    observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
  };
}

function acceptedReceipt(
  command: RuntimeCompensationCommand
): Extract<NonDuplicateRuntimeCompensationReceipt, { outcome: "accepted" }> {
  return {
    ...receiptBase(command),
    outcome: "accepted",
    effectRef: RAW_EFFECT_REF,
  };
}

function enforcedReceipt(
  command: RuntimeCompensationCommand,
  enforcedSafetyFence: number
): RuntimeCompensationReceipt {
  const subject = {
    version: 1 as const,
    purpose: "stale-lifecycle-effect-containment" as const,
    compensationId: command.compensationId,
    commandId: command.commandId,
    commandClaimsDigest: command.authority.claimsDigest,
    binding: command.binding,
    observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
    safetyFence: command.safetyFence,
    enforcedSafetyFence,
    sourceReceiptDigest: command.source.lifecycleReceiptDigest,
    sourceEnforcementSubjectDigest: command.source.lifecycleEnforcementSubjectDigest,
    sourceAggregateProofDigest: command.source.lifecycleAggregateProofDigest,
    requiredContainmentEnforcerSetDigest: command.requiredContainmentEnforcerSetDigest,
    effectRefCommitment: commitRuntimeEffectRef(RAW_EFFECT_REF),
    containment: {
      terminalWritesRevoked: true as const,
      processExecutionStopped: true as const,
      runtimeQuarantined: true as const,
    },
  };
  const payload = {
    generation: command.observedRuntimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest: command.requiredContainmentEnforcerSetDigest,
    enforcementSubjectDigest: digestRuntimeCompensationEnforcementSubject(subject),
    acknowledgements: [
      {
        enforcerRef: "containment-enforcer-1",
        enforcerKind: "runtime" as const,
        acknowledgementDigest: digestFor("containment-acknowledgement"),
      },
    ],
  };
  const aggregateEnforcementProof: AggregateEnforcementProof = {
    ...payload,
    aggregateProofDigest: digestAggregateEnforcementProof(payload),
  };
  return {
    ...receiptBase(command),
    outcome: "enforced",
    effectRef: RAW_EFFECT_REF,
    enforcedSafetyFence,
    containment: subject.containment,
    aggregateEnforcementProof,
  };
}

function leaseCompletion(
  lease: {
    command: RuntimeCompensationCommand;
    attempt: number;
    leaseOwner: string;
    leaseExpiresAtMs: number;
  },
  observedAtMs: number
) {
  return {
    commandId: lease.command.commandId,
    workerId: lease.leaseOwner,
    expectedAttempt: lease.attempt,
    expectedLeaseExpiresAtMs: lease.leaseExpiresAtMs,
    observedAtMs,
  };
}

function dispatchState(db: Database.Database) {
  return db.prepare(`SELECT * FROM runtime_compensation_dispatch`).get();
}

function seedVerifiedCompensationIncident(db: Database.Database): void {
  db.prepare(`INSERT INTO teams (id, name, created_at_ms) VALUES (?, 'Acme', 1)`).run(TEAM_ID);
  db.prepare(
    `INSERT INTO projects (id, team_id, name, created_at_ms)
     VALUES (?, ?, 'Terminal X', 1)`
  ).run(PROJECT_ID, TEAM_ID);
  db.prepare(
    `INSERT INTO sessions (
       id, team_id, project_id, name, status, steering_policy,
       runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms
     ) VALUES (?, ?, ?, 'Session', 'active', 'shared',
       'local-tmux', 'trusted-shared-host', 'compensation-test', 0, 1)`
  ).run(SESSION_ID, TEAM_ID, PROJECT_ID);
  db.prepare(
    `INSERT INTO runtime_assignments (
       id, session_id, team_id, project_id, generation, runtime_kind,
       sandbox_id, sandbox_generation, runtime_principal_id,
       runtime_authorization_generation, status, created_at_ms
     ) VALUES (?, ?, ?, ?, 1, 'local-tmux',
       'sandbox-1', 1, 'principal-1', 1, 'ready', 2)`
  ).run(ASSIGNMENT_ID, SESSION_ID, TEAM_ID, PROJECT_ID);
  db.prepare(
    `INSERT INTO runtime_authorization_epochs (
       session_id, generation, runtime_assignment_id, runtime_assignment_generation,
       sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms,
       effect_enforcer_set_digest
     ) VALUES (?, 1, ?, 1, 'sandbox-1', 1, 'principal-1', 2, ?)`
  ).run(SESSION_ID, ASSIGNMENT_ID, SOURCE_ENFORCER_SET_DIGEST);

  db.transaction(() => {
    db.prepare(
      `INSERT INTO agent_runs (
         id, session_id, team_id, project_id, runtime_assignment_id, lifecycle,
         current_policy_revision, current_goal_set_revision,
         runtime_authorization_generation, created_by_user_id,
         created_at_ms, updated_at_ms
       ) VALUES ('run-1', ?, ?, ?, ?, 'active', 1, 1, 1,
         'user-alice', 10, 10)`
    ).run(SESSION_ID, TEAM_ID, PROJECT_ID, ASSIGNMENT_ID);
    db.prepare(
      `INSERT INTO goal_sets (
         goal_set_id, agent_run_id, revision, previous_revision, digest, created_at_ms
       ) VALUES ('goal-set-1', 'run-1', 1, NULL, ?, 20)`
    ).run(digestFor("goal-set-1"));
    db.prepare(
      `INSERT INTO run_policy_revisions (
         agent_run_id, session_id, revision, previous_revision,
         digest, policy_body_digest, mode, completion_policy,
         scoped_external_policy_ref, scoped_external_rules_json, limits_json,
         initial_goal_set_id, initial_goal_set_revision,
         project_ceiling_revision, project_ceiling_digest,
         runtime_assignment_id, runtime_assignment_generation,
         sandbox_id, sandbox_generation, runtime_principal_id,
         runtime_authorization_generation, required_effect_enforcer_set_digest,
         yolo_confirmation_ref, created_at_ms
       ) VALUES (
         'run-1', ?, 1, NULL, ?, ?, 'autonomous',
         'continue-until-all-goals-achieved', 'scoped-policy-1', '[]', ?,
         'goal-set-1', 1, 'ceiling-1', ?, ?, 1,
         'sandbox-1', 1, 'principal-1', 1, ?, NULL, 20
       )`
    ).run(
      SESSION_ID,
      digestFor("policy"),
      digestFor("policy-body"),
      JSON.stringify(completeLimits()),
      digestFor("ceiling"),
      ASSIGNMENT_ID,
      SOURCE_ENFORCER_SET_DIGEST
    );
  })();

  const sourceCommandDigest = digestFor(SOURCE_COMMAND_ID);
  const sourceAuthorityDigest = digestFor("source-authority");
  const binding = runtimeBinding();
  const commandJson = JSON.stringify({
    commandId: SOURCE_COMMAND_ID,
    kind: "run.pause",
    agentRunId: "run-1",
    runPolicyRevision: 1,
    fromRunStateVersion: 1,
    toRunStateVersion: 2,
    projectCeilingRevision: "ceiling-1",
    causationId: "event:pause-requested",
    actor: { kind: "human", actorRef: "user-alice" },
    issuedAtMs: 100,
    deadlineAtMs: 200,
    authority: {
      issuer: "team-session",
      issuerKeyId: "team-session-key-1",
      audience: "runtime",
      capability: "run.pause",
      claimsDigest: sourceAuthorityDigest,
      issuedAtMs: 100,
      expiresAtMs: 200,
      signature: "source-signature",
    },
    runtimeAuthorizationGeneration: 1,
    requiredEffectEnforcerSetDigest: SOURCE_ENFORCER_SET_DIGEST,
    binding,
    reason: "human",
  });
  db.prepare(
    `INSERT INTO session_events (
       session_id, sequence, event_id, type, occurred_at_ms,
       actor_kind, actor_user_id, actor_display_name,
       source_scope, source_key, payload_json
     ) VALUES (?, 1, 'event:pause-requested', 'run.runtime-command.requested', 100,
       'human', 'user-alice', 'Alice', 'vitest:runtime-command',
       'event:pause-requested', ?)`
  ).run(
    SESSION_ID,
    JSON.stringify({
      commandId: SOURCE_COMMAND_ID,
      agentRunId: "run-1",
      operation: "run.pause",
      fromRunStateVersion: 1,
      toRunStateVersion: 2,
      targetLifecycle: "paused",
    })
  );
  db.prepare(`UPDATE sessions SET next_sequence = 2 WHERE id = ?`).run(SESSION_ID);

  db.transaction(() => {
    db.prepare(
      `INSERT INTO runtime_run_commands (
         id, session_id, agent_run_id, command_sequence, previous_command_sequence,
         operation, target_lifecycle, expected_run_state_version,
         target_run_state_version, run_policy_revision, goal_set_id, goal_set_revision,
         runtime_assignment_id, runtime_assignment_generation, sandbox_id,
         sandbox_generation, runtime_principal_id, runtime_authorization_generation,
         required_effect_enforcer_set_digest, source_session_sequence,
         command_json, command_digest, authority_digest, created_at_ms, deadline_at_ms
       ) VALUES (?, ?, 'run-1', 1, NULL, 'run.pause', 'paused', 1, 2,
         1, 'goal-set-1', 1, ?, 1, 'sandbox-1', 1, 'principal-1', 1,
         ?, 1, ?, ?, ?, 100, 200)`
    ).run(
      SOURCE_COMMAND_ID,
      SESSION_ID,
      ASSIGNMENT_ID,
      SOURCE_ENFORCER_SET_DIGEST,
      commandJson,
      sourceCommandDigest,
      sourceAuthorityDigest
    );
    db.prepare(
      `INSERT INTO runtime_run_command_dispatch (
         command_id, agent_run_id, status, attempts, available_at_ms,
         created_at_ms, updated_at_ms
       ) VALUES (?, 'run-1', 'pending', 0, 100, 100, 100)`
    ).run(SOURCE_COMMAND_ID);
  })();
  db.prepare(
    `UPDATE runtime_run_command_dispatch
     SET status = 'processing', attempts = 1, lease_owner = 'source-worker',
         lease_expires_at_ms = 200, updated_at_ms = 101
     WHERE command_id = ?`
  ).run(SOURCE_COMMAND_ID);
  db.prepare(
    `UPDATE runtime_run_command_dispatch
     SET dispatch_interlock_acquired_at_ms = 101
     WHERE command_id = ?`
  ).run(SOURCE_COMMAND_ID);

  const sourceEffectCommitment = `effect:v1:${digestFor("source-effect")}`;
  const sourceReceiptDigest = digestFor(SOURCE_RECEIPT_ID);
  const sourceReceiptJson = JSON.stringify({
    commandId: SOURCE_COMMAND_ID,
    binding,
    runtimeAuthorizationGeneration: 1,
    outcome: "enforced",
    effectRef: sourceEffectCommitment,
    enforcedFence: 2,
    aggregateEnforcementProof: {
      generation: 1,
      requiredEffectEnforcerSetDigest: SOURCE_ENFORCER_SET_DIGEST,
      enforcementSubjectDigest: SOURCE_SUBJECT_DIGEST,
      acknowledgements: [
        {
          enforcerRef: "source-enforcer-1",
          enforcerKind: "runtime",
          acknowledgementDigest: digestFor("source-acknowledgement"),
        },
      ],
      aggregateProofDigest: SOURCE_PROOF_DIGEST,
    },
  });
  db.prepare(
    `INSERT INTO runtime_run_command_receipts (
       id, command_id, version, previous_version, session_id, agent_run_id,
       command_sequence, run_policy_revision, goal_set_id, goal_set_revision,
       runtime_assignment_id, runtime_assignment_generation, sandbox_id,
       sandbox_generation, runtime_principal_id, runtime_authorization_generation,
       expected_run_state_version, target_run_state_version, source_session_sequence,
       command_digest, outcome, original_outcome, original_receipt_digest,
       receipt_json, receipt_digest, received_at_ms,
       required_effect_enforcer_set_digest, enforcement_subject_digest,
       aggregate_proof_digest, proof_verified_at_ms
     ) VALUES (?, ?, 1, NULL, ?, 'run-1', 1, 1, 'goal-set-1', 1,
       ?, 1, 'sandbox-1', 1, 'principal-1', 1, 1, 2, 1,
       ?, 'enforced', NULL, NULL, ?, ?, 110, ?, ?, ?, 110)`
  ).run(
    SOURCE_RECEIPT_ID,
    SOURCE_COMMAND_ID,
    SESSION_ID,
    ASSIGNMENT_ID,
    sourceCommandDigest,
    sourceReceiptJson,
    sourceReceiptDigest,
    SOURCE_ENFORCER_SET_DIGEST,
    SOURCE_SUBJECT_DIGEST,
    SOURCE_PROOF_DIGEST
  );
  db.prepare(
    `UPDATE runtime_binding_safety_fences
     SET allocated_fence = 3, updated_at_ms = 110
     WHERE runtime_assignment_id = ?`
  ).run(ASSIGNMENT_ID);

  const incident: RuntimeCompensationIncident = {
    version: 1,
    compensationId: COMPENSATION_ID,
    sourceCommandId: SOURCE_COMMAND_ID,
    sourceReceiptId: SOURCE_RECEIPT_ID,
    trustState: "verified",
    binding,
    observedRuntimeAuthorizationGeneration: 1,
    lifecycleCommandClaimsDigest: sourceAuthorityDigest,
    lifecycleReceiptDigest: sourceReceiptDigest,
    sourceEnforcedFence: 2,
    safetyFence: 3,
    sourceRequiredEffectEnforcerSetDigest: SOURCE_ENFORCER_SET_DIGEST,
    lifecycleEnforcementSubjectDigest: SOURCE_SUBJECT_DIGEST,
    lifecycleAggregateProofDigest: SOURCE_PROOF_DIGEST,
    sourceEffectRefCommitment: snapshotPersistedRuntimeEffectRefCommitment(sourceEffectCommitment),
    createdAtMs: 110,
  };
  const incidentDigest = digestRuntimeCompensationIncident(incident);
  db.prepare(
    `INSERT INTO runtime_compensation_incidents (
       compensation_id, incident_digest, source_command_id, source_receipt_id, trust_state,
       session_id, team_id, project_id, agent_run_id, run_policy_revision,
       runtime_assignment_id, runtime_assignment_generation,
       sandbox_id, sandbox_generation, runtime_principal_id,
       runtime_authorization_generation, source_command_digest,
       lifecycle_command_claims_digest, lifecycle_receipt_digest,
       source_enforced_fence, safety_fence, source_effect_ref_commitment,
       source_required_effect_enforcer_set_digest,
       lifecycle_enforcement_subject_digest, lifecycle_aggregate_proof_digest,
       source_proof_verified_at_ms, created_at_ms
     ) VALUES (?, ?, ?, ?, 'verified', ?, ?, ?, 'run-1', 1,
       ?, 1, 'sandbox-1', 1, 'principal-1', 1, ?, ?, ?, 2, 3, ?, ?, ?, ?, 110, 110)`
  ).run(
    COMPENSATION_ID,
    incidentDigest,
    SOURCE_COMMAND_ID,
    SOURCE_RECEIPT_ID,
    SESSION_ID,
    TEAM_ID,
    PROJECT_ID,
    ASSIGNMENT_ID,
    sourceCommandDigest,
    sourceAuthorityDigest,
    sourceReceiptDigest,
    sourceEffectCommitment,
    SOURCE_ENFORCER_SET_DIGEST,
    SOURCE_SUBJECT_DIGEST,
    SOURCE_PROOF_DIGEST
  );
  db.prepare(
    `UPDATE runtime_run_command_dispatch
     SET status = 'compensating', lease_owner = NULL, lease_expires_at_ms = NULL,
         last_safe_error_code = 'stale_enforced_effect', updated_at_ms = 110
     WHERE command_id = ?`
  ).run(SOURCE_COMMAND_ID);
}

function runtimeBinding() {
  return {
    teamId: TEAM_ID,
    projectId: PROJECT_ID,
    sessionId: SESSION_ID,
    runtimeAssignmentId: ASSIGNMENT_ID,
    runtimeAssignmentGeneration: 1,
    sandboxId: "sandbox-1",
    sandboxGeneration: 1,
    runtimePrincipalId: "principal-1",
  };
}

function completeLimits() {
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

function digestFor(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
