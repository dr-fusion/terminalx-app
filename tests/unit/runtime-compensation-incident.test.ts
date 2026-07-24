import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalRuntimeJson } from "@/lib/runtime/runtime-command-canonical";
import {
  RUNTIME_COMPENSATION_INCIDENT_DIGEST_DOMAIN,
  RuntimeCompensationIncidentError,
  digestRuntimeCompensationIncident,
  snapshotRuntimeCompensationIncident,
  type RuntimeCompensationIncident,
} from "@/lib/runtime/runtime-compensation-incident";
import { commitRuntimeEffectRef } from "@/lib/runtime/runtime-enforcement-proof";

const binding = {
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 2,
  sandboxId: "sandbox-1",
  sandboxGeneration: 3,
  runtimePrincipalId: "principal-1",
} as const;

const verifiedIncident = {
  version: 1,
  compensationId: "compensation-1",
  sourceCommandId: "lifecycle-command-1",
  sourceReceiptId: "lifecycle-receipt-1",
  trustState: "verified",
  binding,
  observedRuntimeAuthorizationGeneration: 4,
  lifecycleCommandClaimsDigest: "a".repeat(64),
  lifecycleReceiptDigest: "b".repeat(64),
  sourceEnforcedFence: 7,
  safetyFence: 8,
  sourceRequiredEffectEnforcerSetDigest: "c".repeat(64),
  lifecycleEnforcementSubjectDigest: "d".repeat(64),
  lifecycleAggregateProofDigest: "e".repeat(64),
  sourceEffectRefCommitment: commitRuntimeEffectRef("provider-source-effect"),
  createdAtMs: 2_000_000_000_000,
} as const satisfies RuntimeCompensationIncident;

const legacyIncident = {
  ...verifiedIncident,
  compensationId: "migration-v7:incident-1",
  trustState: "legacy-untrusted",
  sourceRequiredEffectEnforcerSetDigest: null,
  lifecycleEnforcementSubjectDigest: null,
  lifecycleAggregateProofDigest: null,
  sourceEffectRefCommitment: null,
} as const satisfies RuntimeCompensationIncident;

describe("Runtime compensation incident", () => {
  it("snapshots and freezes complete verified source evidence", () => {
    const snapshot = snapshotRuntimeCompensationIncident(verifiedIncident);

    expect(snapshot).toEqual(verifiedIncident);
    expect(snapshot).not.toBe(verifiedIncident);
    expect(snapshot.binding).not.toBe(binding);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.binding)).toBe(true);
  });

  it("uses one domain-separated canonical digest independent of property order", () => {
    const reordered = {
      createdAtMs: verifiedIncident.createdAtMs,
      sourceEffectRefCommitment: verifiedIncident.sourceEffectRefCommitment,
      lifecycleAggregateProofDigest: verifiedIncident.lifecycleAggregateProofDigest,
      lifecycleEnforcementSubjectDigest: verifiedIncident.lifecycleEnforcementSubjectDigest,
      sourceRequiredEffectEnforcerSetDigest: verifiedIncident.sourceRequiredEffectEnforcerSetDigest,
      safetyFence: verifiedIncident.safetyFence,
      sourceEnforcedFence: verifiedIncident.sourceEnforcedFence,
      lifecycleReceiptDigest: verifiedIncident.lifecycleReceiptDigest,
      lifecycleCommandClaimsDigest: verifiedIncident.lifecycleCommandClaimsDigest,
      observedRuntimeAuthorizationGeneration:
        verifiedIncident.observedRuntimeAuthorizationGeneration,
      binding: {
        runtimePrincipalId: binding.runtimePrincipalId,
        sandboxGeneration: binding.sandboxGeneration,
        sandboxId: binding.sandboxId,
        runtimeAssignmentGeneration: binding.runtimeAssignmentGeneration,
        runtimeAssignmentId: binding.runtimeAssignmentId,
        sessionId: binding.sessionId,
        projectId: binding.projectId,
        teamId: binding.teamId,
      },
      trustState: verifiedIncident.trustState,
      sourceReceiptId: verifiedIncident.sourceReceiptId,
      sourceCommandId: verifiedIncident.sourceCommandId,
      compensationId: verifiedIncident.compensationId,
      version: 1 as const,
    };
    expect(RUNTIME_COMPENSATION_INCIDENT_DIGEST_DOMAIN).toBe(
      "terminalx/runtime-compensation-incident/v1\0"
    );
    const expected = createHash("sha256")
      .update("terminalx/runtime-compensation-incident/v1\0", "utf8")
      .update(canonicalRuntimeJson(verifiedIncident), "utf8")
      .digest("hex");

    expect(digestRuntimeCompensationIncident(verifiedIncident)).toBe(expected);
    expect(digestRuntimeCompensationIncident(reordered)).toBe(expected);
    expect(expected).toMatch(/^[0-9a-f]{64}$/);
  });

  it("retains legacy incidents only when every proof field is null", () => {
    expect(snapshotRuntimeCompensationIncident(legacyIncident)).toEqual(legacyIncident);

    for (const mutation of [
      { ...legacyIncident, sourceRequiredEffectEnforcerSetDigest: "c".repeat(64) },
      { ...legacyIncident, lifecycleEnforcementSubjectDigest: "d".repeat(64) },
      { ...legacyIncident, lifecycleAggregateProofDigest: "e".repeat(64) },
      {
        ...legacyIncident,
        sourceEffectRefCommitment: commitRuntimeEffectRef("partial-legacy-proof"),
      },
    ]) {
      expect(() => snapshotRuntimeCompensationIncident(mutation)).toThrow(
        RuntimeCompensationIncidentError
      );
    }
  });

  it("rejects incomplete verified evidence and invalid monotonic fences", () => {
    for (const mutation of [
      { ...verifiedIncident, sourceRequiredEffectEnforcerSetDigest: null },
      { ...verifiedIncident, lifecycleEnforcementSubjectDigest: null },
      { ...verifiedIncident, lifecycleAggregateProofDigest: null },
      { ...verifiedIncident, sourceEffectRefCommitment: null },
      { ...verifiedIncident, sourceEffectRefCommitment: "provider-raw-effect" },
      { ...verifiedIncident, sourceRequiredEffectEnforcerSetDigest: "C".repeat(64) },
      { ...verifiedIncident, sourceEnforcedFence: 0 },
      { ...verifiedIncident, safetyFence: verifiedIncident.sourceEnforcedFence },
      { ...verifiedIncident, safetyFence: Number.MAX_SAFE_INTEGER + 1 },
      { ...verifiedIncident, observedRuntimeAuthorizationGeneration: 0 },
      { ...verifiedIncident, createdAtMs: -1 },
    ]) {
      expect(() => snapshotRuntimeCompensationIncident(mutation)).toThrow(
        RuntimeCompensationIncidentError
      );
    }
  });

  it("rejects missing, extra, accessor, symbolic, and exotic fields without invoking getters", () => {
    let getterCalls = 0;
    const accessor = { ...verifiedIncident } as Record<string, unknown>;
    Object.defineProperty(accessor, "compensationId", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return verifiedIncident.compensationId;
      },
    });
    const symbolic = { ...verifiedIncident, [Symbol("hidden")]: true };
    const missing = { ...verifiedIncident } as Record<string, unknown>;
    delete missing.sourceReceiptId;
    const exotic = Object.assign(Object.create({ inherited: true }), verifiedIncident);

    for (const value of [
      { ...verifiedIncident, unexpected: true },
      missing,
      accessor,
      symbolic,
      exotic,
      [],
      null,
    ]) {
      expect(() => snapshotRuntimeCompensationIncident(value)).toThrow(
        RuntimeCompensationIncidentError
      );
    }
    expect(getterCalls).toBe(0);
  });

  it("rejects accessor binding fields without invoking them", () => {
    let getterCalls = 0;
    const hostileBinding = { ...binding } as Record<string, unknown>;
    Object.defineProperty(hostileBinding, "sandboxId", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return binding.sandboxId;
      },
    });

    expect(() =>
      snapshotRuntimeCompensationIncident({ ...verifiedIncident, binding: hostileBinding })
    ).toThrow(RuntimeCompensationIncidentError);
    expect(getterCalls).toBe(0);
  });

  it("binds every incident field and keeps verified and legacy trust distinct", () => {
    const expected = digestRuntimeCompensationIncident(verifiedIncident);
    const mutations: RuntimeCompensationIncident[] = [
      { ...verifiedIncident, compensationId: "compensation-2" },
      { ...verifiedIncident, sourceCommandId: "lifecycle-command-2" },
      { ...verifiedIncident, sourceReceiptId: "lifecycle-receipt-2" },
      { ...verifiedIncident, binding: { ...binding, sandboxGeneration: 4 } },
      { ...verifiedIncident, observedRuntimeAuthorizationGeneration: 5 },
      { ...verifiedIncident, lifecycleCommandClaimsDigest: "0".repeat(64) },
      { ...verifiedIncident, lifecycleReceiptDigest: "1".repeat(64) },
      { ...verifiedIncident, sourceEnforcedFence: 6 },
      { ...verifiedIncident, safetyFence: 9 },
      { ...verifiedIncident, sourceRequiredEffectEnforcerSetDigest: "2".repeat(64) },
      { ...verifiedIncident, lifecycleEnforcementSubjectDigest: "3".repeat(64) },
      { ...verifiedIncident, lifecycleAggregateProofDigest: "4".repeat(64) },
      {
        ...verifiedIncident,
        sourceEffectRefCommitment: commitRuntimeEffectRef("another-source-effect"),
      },
      { ...verifiedIncident, createdAtMs: verifiedIncident.createdAtMs + 1 },
    ];

    for (const mutation of mutations) {
      expect(digestRuntimeCompensationIncident(mutation)).not.toBe(expected);
    }
    expect(digestRuntimeCompensationIncident(legacyIncident)).not.toBe(expected);
  });
});
