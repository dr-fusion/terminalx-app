import { describe, expect, expectTypeOf, it } from "vitest";
import type {
  ActionControlSessionCommand,
  ActionGrant,
  ActionManifest,
  AgentRunSessionCommand,
  ApprovalRequest,
  GoalSet,
  GrantReview,
  RunLimit,
  RunLimits,
  RunActionPattern,
  RunPolicyRevision,
  SessionRunStateQuery,
} from "@/lib/team-sessions";
import type {
  Runtime,
  RuntimeCommand,
  RuntimeEvent,
  RuntimeHandle,
  RuntimeSpec,
} from "@/lib/runtime";

describe("portable multiplayer Phase 4 contracts", () => {
  it("preserves configured and unconfigured Run limits as explicit discriminants", () => {
    const unconfigured = { kind: "unconfigured" } as const satisfies RunLimit<number>;
    const capped = { kind: "capped", value: 10_000 } as const satisfies RunLimit<number>;
    const limits = {
      wallClock: unconfigured,
      modelTokens: capped,
      modelSpend: unconfigured,
      outboundBytes: unconfigured,
      actionCounts: {
        local: unconfigured,
        "scoped-external": unconfigured,
        protected: capped,
        forbidden: { kind: "capped", value: 0 },
      },
    } as const satisfies RunLimits;

    expect(limits.modelTokens).toEqual({ kind: "capped", value: 10_000 });
    expect(limits.wallClock).toEqual({ kind: "unconfigured" });
    expectTypeOf<RunLimits["modelTokens"]>().not.toEqualTypeOf<number | null | undefined>();
  });

  it("exports closed Session command and actor-scoped Run-state discriminants", () => {
    expectTypeOf<AgentRunSessionCommand["type"]>().toEqualTypeOf<
      | "run.start"
      | "run.policy.revise"
      | "run.pause"
      | "run.resume"
      | "run.stop"
      | "run.emergency-stop"
      | "goal.add"
      | "goal.criteria.strengthen"
      | "goal.dependency.add"
      | "goal.reorder"
      | "goal.evidence.review"
      | "run.final-review.resolve"
    >();
    expectTypeOf<ActionControlSessionCommand["type"]>().toEqualTypeOf<
      "approval.resolve" | "grant.revoke" | "grant.review.resolve" | "attention.resolve"
    >();
    expectTypeOf<SessionRunStateQuery["type"]>().toEqualTypeOf<"session.run-state">();
  });

  it("binds policies, manifests, and grants to portable Runtime generations", () => {
    expectTypeOf<RunPolicyRevision["binding"]>().toHaveProperty("runtimeAssignmentGeneration");
    expectTypeOf<RunPolicyRevision["binding"]>().toHaveProperty("sandboxGeneration");
    expectTypeOf<ActionManifest["credentialRef"]>().toEqualTypeOf<string | undefined>();
    expectTypeOf<ActionGrant>().toHaveProperty("runtimeAuthorizationGeneration");
    expectTypeOf<ApprovalRequest["actionClass"]>().toEqualTypeOf<"scoped-external" | "protected">();
    expectTypeOf<ActionGrant["actionClass"]>().toEqualTypeOf<"scoped-external" | "protected">();
    expectTypeOf<
      Extract<ActionGrant, { actionClass: "protected" }>["scope"]["kind"]
    >().toEqualTypeOf<"once">();
    expectTypeOf<RunActionPattern["actionClass"]>().toEqualTypeOf<"scoped-external">();
    expectTypeOf<GrantReview["safeDefault"]>().toEqualTypeOf<"revoke-all">();
    expectTypeOf<GrantReview["target"]["runtimeBinding"]>().toHaveProperty("sandboxGeneration");
    expectTypeOf<ActionGrant["scope"]>().toMatchTypeOf<
      | { readonly kind: "once" }
      | {
          readonly kind: "run";
          readonly eligibleUse:
            | "session_branch_push"
            | "draft_pull_request_update"
            | "ephemeral_preview_update"
            | "same_credential_nonproduction_target";
        }
    >();
  });

  it("keeps Runtime provider details behind the four-method Interface", () => {
    expectTypeOf<keyof Runtime>().toEqualTypeOf<"ensure" | "command" | "follow" | "retire">();
    expectTypeOf<
      Extract<RuntimeCommand, { kind: "run.start" }>["policy"]
    >().toEqualTypeOf<RunPolicyRevision>();
    expectTypeOf<
      Extract<RuntimeEvent, { kind: "goal-set.applied" }>["payload"]["goalSet"]
    >().toEqualTypeOf<GoalSet>();

    const adapter: Runtime = createCompileTimeAdapter();
    expect(Object.keys(adapter).sort()).toEqual(["command", "ensure", "follow", "retire"]);
  });
});

function createCompileTimeAdapter(): Runtime {
  return {
    async ensure(spec: RuntimeSpec): Promise<RuntimeHandle> {
      return {
        binding: spec.binding,
        opaqueHandleRef: "opaque-runtime-handle",
        capabilities: {
          isolatedExecution: false,
          brokeredCredentials: false,
          proxyOnlyEgress: false,
          checkpoints: false,
          yoloEligible: false,
        },
      };
    },
    async command(handle, command, signal) {
      if (signal.aborted) throw new Error("Runtime command cancelled");
      return {
        commandId: command.commandId,
        binding: handle.binding,
        runtimeAuthorizationGeneration:
          "runtimeAuthorizationGeneration" in command
            ? command.runtimeAuthorizationGeneration
            : command.observedRuntimeAuthorizationGeneration,
        outcome: "accepted",
        effectRef: "effect-1",
      };
    },
    async *follow() {
      return;
    },
    async retire() {
      return;
    },
  };
}
