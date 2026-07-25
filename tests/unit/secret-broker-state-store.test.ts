import { describe, expect, it } from "vitest";
import {
  openSecretBrokerStateStore,
  type PreparedRegistrationInput,
  type SecretBrokerStateStore,
} from "../../packages/secret-broker/src/state-store";
import { SecretBrokerProtocolError } from "../../packages/secret-broker/src/protocol";

function store(clock?: () => number): SecretBrokerStateStore {
  return openSecretBrokerStateStore({ databasePath: ":memory:", clock });
}

let counter = 0;
function prepareInput(
  overrides: Partial<PreparedRegistrationInput> = {}
): PreparedRegistrationInput {
  counter += 1;
  return {
    operationId: `op_${counter}`,
    handleId: `hnd_${counter}`,
    receiptId: `rcp_${counter}`,
    provider: "slack",
    brokerKind: "oauth-envelope",
    usage: "installation",
    expectationDigest: "a".repeat(64),
    replacesHandleId: null,
    issuedAtMs: 1000,
    expiresAtMs: 1000 + 300_000,
    secretMaterial: Buffer.from("secret-material"),
    ...overrides,
  };
}

describe("Secret Broker state store", () => {
  it("prepares a pending row and is idempotent by operationId", () => {
    const s = store();
    const input = prepareInput();
    const first = s.prepare({ ...input, secretMaterial: Buffer.from("s") });
    expect(first.status).toBe("pending");
    expect(first.hasSecretMaterial).toBe(true);
    const retry = s.prepare({ ...input, secretMaterial: Buffer.from("s") });
    expect(retry.handleId).toBe(first.handleId);
    expect(retry.receiptId).toBe(first.receiptId);
    expect(s.countPending()).toBe(1);
  });

  it("rejects a reused operationId that changes the binding", () => {
    const s = store();
    const input = prepareInput();
    s.prepare({ ...input, secretMaterial: Buffer.from("s") });
    expect(() =>
      s.prepare({ ...input, expectationDigest: "b".repeat(64), secretMaterial: Buffer.from("s") })
    ).toThrow(SecretBrokerProtocolError);
  });

  it("finalizes pending to active idempotently and rejects a wrong receipt", () => {
    const s = store();
    const row = s.prepare(prepareInput());
    const active = s.finalize(row.handleId, row.receiptId);
    expect(active.status).toBe("active");
    expect(s.finalize(row.handleId, row.receiptId).status).toBe("active");
    expect(() => s.finalize(row.handleId, "rcp_wrong")).toThrow(SecretBrokerProtocolError);
    expect(() => s.finalize("hnd_missing", row.receiptId)).toThrow(SecretBrokerProtocolError);
  });

  it("aborts pending, nulls the secret, and is idempotent; refuses to abort active", () => {
    const s = store();
    const row = s.prepare(prepareInput());
    const aborted = s.abort(row.receiptId);
    expect(aborted.status).toBe("aborted");
    expect(aborted.hasSecretMaterial).toBe(false);
    expect(s.abort(row.receiptId).status).toBe("aborted");

    const active = s.prepare(prepareInput());
    s.finalize(active.handleId, active.receiptId);
    expect(() => s.abort(active.receiptId)).toThrow(SecretBrokerProtocolError);
  });

  it("revokes active, nulls the secret, is idempotent, and refuses to revoke pending", () => {
    const s = store();
    const row = s.prepare(prepareInput());
    expect(() => s.revoke(row.handleId)).toThrow(SecretBrokerProtocolError);
    s.finalize(row.handleId, row.receiptId);
    const revoked = s.revoke(row.handleId);
    expect(revoked.status).toBe("revoked");
    expect(revoked.hasSecretMaterial).toBe(false);
    expect(s.revoke(row.handleId).status).toBe("revoked");
  });

  it("reaps only expired pending rows and nulls their secrets", () => {
    const s = store();
    const expired = s.prepare(prepareInput({ expiresAtMs: 5000 }));
    const fresh = s.prepare(prepareInput({ expiresAtMs: 50_000 }));
    const reaped = s.reapExpiredPending(10_000);
    expect(reaped.map((row) => row.handleId)).toEqual([expired.handleId]);
    expect(s.getByHandleId(expired.handleId)?.status).toBe("aborted");
    expect(s.getByHandleId(expired.handleId)?.hasSecretMaterial).toBe(false);
    expect(s.getByHandleId(fresh.handleId)?.status).toBe("pending");
  });

  it("keeps the replaced secret until rotation finalizes, then revokes it", () => {
    const s = store();
    const original = s.prepare(prepareInput());
    s.finalize(original.handleId, original.receiptId);
    const replacement = s.prepare(prepareInput({ replacesHandleId: original.handleId }));
    // Before finalize the replaced secret is intact.
    expect(s.getByHandleId(original.handleId)?.status).toBe("active");
    expect(s.getByHandleId(original.handleId)?.hasSecretMaterial).toBe(true);

    const finalized = s.finalizeRotation(replacement.handleId, replacement.receiptId);
    expect(finalized.status).toBe("active");
    expect(s.getByHandleId(original.handleId)?.status).toBe("revoked");
    expect(s.getByHandleId(original.handleId)?.hasSecretMaterial).toBe(false);
    // Idempotent.
    expect(s.finalizeRotation(replacement.handleId, replacement.receiptId).status).toBe("active");
  });

  it("aborting a rotation leaves the replaced handle active with its secret", () => {
    const s = store();
    const original = s.prepare(prepareInput());
    s.finalize(original.handleId, original.receiptId);
    const replacement = s.prepare(prepareInput({ replacesHandleId: original.handleId }));
    const aborted = s.abort(replacement.receiptId);
    expect(aborted.status).toBe("aborted");
    expect(s.getByHandleId(original.handleId)?.status).toBe("active");
    expect(s.getByHandleId(original.handleId)?.hasSecretMaterial).toBe(true);
  });
});
