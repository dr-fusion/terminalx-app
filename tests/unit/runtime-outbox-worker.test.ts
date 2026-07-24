import { describe, expect, it } from "vitest";
import {
  CANONICAL_TMUX_SOCKET_NAME_ENV,
  LocalTmuxRuntime,
  RuntimeEffectError,
  RuntimeOutboxWorker,
  canonicalTmuxTarget,
  getCanonicalTmuxSocketName,
  type ExactCommandExecutor,
  type ExactCommandRequest,
  type ExactCommandResult,
  type CanonicalPtyTermination,
  type RuntimeOutboxApplier,
  type RuntimeOutboxKernel,
  type RuntimeWriteStateUpdate,
} from "@/lib/runtime";
import type {
  CommandResult,
  RuntimeOutboxClaimOptions,
  RuntimeOutboxDelivery,
  SessionCommand,
} from "@/lib/team-sessions";

const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const SECOND_SESSION_ID = "44444444-4444-4444-8444-444444444444";
const SESSION_INCARNATION = "a".repeat(64);
const REPLACEMENT_SESSION_INCARNATION = "b".repeat(64);

function marker(sessionId = SESSION_ID, sessionIncarnation = SESSION_INCARNATION): string {
  return `v2:${sessionId}:${sessionIncarnation}\n`;
}

function sessionLine(
  tmuxName = "canonical-agent",
  generation = 1,
  sessionId = SESSION_ID,
  tmuxSessionRef = "$1",
  sessionIncarnation = SESSION_INCARNATION
): string {
  return `${tmuxName}\t1\t${sessionId}\t${generation}\t${tmuxSessionRef}\t${sessionIncarnation}\tv2:${sessionId}:${sessionIncarnation}\n`;
}

function delivery(
  kind: RuntimeOutboxDelivery["kind"],
  generation = 1,
  attempts = 1,
  sessionId = SESSION_ID,
  tmuxName = "canonical-agent",
  dispatchMode: RuntimeOutboxDelivery["dispatchMode"] = "apply"
): RuntimeOutboxDelivery {
  const base = {
    outboxId: `outbox-${kind}-${generation}`,
    sessionId,
    sessionSequence: generation,
    attempts,
    leaseOwner: "runtime-worker-1",
    leaseExpiresAtMs: 2_000_000_030_000,
    dispatchMode,
  };
  switch (kind) {
    case "runtime.session.ensure":
      return {
        ...base,
        kind,
        payload: {
          sessionId,
          runtimeKind: "local-tmux",
          tmuxName,
          runtimeAuthorizationGeneration: generation,
        },
      };
    case "runtime.authorization.fence":
      return {
        ...base,
        kind,
        payload: {
          sessionId,
          reason: "assignee-loss",
          runtimeAuthorizationGeneration: generation,
        },
      };
    case "runtime.session.retire":
      return {
        ...base,
        kind,
        payload: {
          sessionId,
          runtimeAuthorizationGeneration: generation,
          reason: "emergency-stop",
          agentRunId: "run-one",
          runtimeAssignmentId: "assignment-one",
          runtimeAssignmentGeneration: 1,
          sandboxId: "sandbox-one",
          sandboxGeneration: 1,
        },
      };
  }
}

function emergencyRetireDelivery(
  generation = 1
): Extract<RuntimeOutboxDelivery, { kind: "runtime.session.retire" }> {
  const base = delivery("runtime.session.retire", generation);
  if (base.kind !== "runtime.session.retire") throw new Error("Expected retire delivery");
  return {
    ...base,
    payload: {
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: generation,
      reason: "emergency-stop",
      agentRunId: "run-one",
      runtimeAssignmentId: "assignment-one",
      runtimeAssignmentGeneration: 1,
      sandboxId: "sandbox-one",
      sandboxGeneration: 1,
    },
  };
}

function hostedDelivery(kind: RuntimeOutboxDelivery["kind"]): RuntimeOutboxDelivery {
  const generation = 1;
  const binding = {
    teamId: "team-one",
    projectId: "project-one",
    sessionId: SESSION_ID,
    runtimeAssignmentId: "assignment-one",
    runtimeAssignmentGeneration: 1,
    sandboxId: "sandbox-one",
    sandboxGeneration: 1,
    runtimePrincipalId: "principal-one",
  } as const;
  const base = {
    outboxId: `hosted-${kind}`,
    sessionId: SESSION_ID,
    sessionSequence: generation,
    attempts: 1,
    leaseOwner: "runtime-worker-1",
    leaseExpiresAtMs: 2_000_000_030_000,
    dispatchMode: "apply" as const,
  };
  const hosted = {
    runtimeKind: "daytona" as const,
    binding,
    assignmentPlanRef: "hosted-plan-one",
    assignmentPlanDigest: "a".repeat(64),
  };
  switch (kind) {
    case "runtime.session.ensure":
      return {
        ...base,
        kind,
        payload: {
          sessionId: SESSION_ID,
          runtimeAuthorizationGeneration: generation,
          ...hosted,
        },
      };
    case "runtime.authorization.fence":
      return {
        ...base,
        kind,
        payload: {
          sessionId: SESSION_ID,
          reason: "assignee-loss",
          runtimeAuthorizationGeneration: generation,
          ...hosted,
        },
      };
    case "runtime.session.retire":
      return {
        ...base,
        kind,
        payload: {
          sessionId: SESSION_ID,
          runtimeAuthorizationGeneration: generation,
          reason: "emergency-stop",
          agentRunId: "run-one",
          runtimeAssignmentId: binding.runtimeAssignmentId,
          runtimeAssignmentGeneration: binding.runtimeAssignmentGeneration,
          sandboxId: binding.sandboxId,
          sandboxGeneration: binding.sandboxGeneration,
          ...hosted,
        },
      };
  }
}

function success(stdout = ""): ExactCommandResult {
  return { ok: true, stdout, stderr: "" };
}

function failure(stderr: string): ExactCommandResult {
  return { ok: false, failure: "exit", exitCode: 1, stdout: "", stderr };
}

class ScriptedExecutor implements ExactCommandExecutor {
  readonly requests: ExactCommandRequest[] = [];

  constructor(
    private readonly results: ExactCommandResult[],
    private readonly log?: string[]
  ) {}

  async execute(request: ExactCommandRequest): Promise<ExactCommandResult> {
    this.requests.push(request);
    this.log?.push(`exec:${operation(request.args)}`);
    if (request.signal.aborted) {
      return { ok: false, failure: "aborted", stdout: "", stderr: "" };
    }
    const result = this.results.shift();
    if (!result) throw new Error("Unexpected executor call");
    return result;
  }
}

function operation(args: readonly string[]): string {
  if (args[4] === "if-shell") return guardedCommand(args)?.split(" ")[0] ?? "if-shell";
  return args[4] ?? "unknown";
}

function guardedCommand(args: readonly string[]): string | undefined {
  return args[4] === "if-shell" ? args[9] : undefined;
}

function runtimeWith(
  executor: ExactCommandExecutor,
  options: {
    log?: string[];
    states?: RuntimeWriteStateUpdate[];
    ensureState?:
      | "pending"
      | "enforced"
      | "stale"
      | (() => "pending" | "enforced" | "stale" | Promise<"pending" | "enforced" | "stale">);
    ensureInputs?: unknown[];
    currentBinding?: boolean;
    bindingInputs?: unknown[];
    terminationInputs?: CanonicalPtyTermination[];
  } = {}
) {
  const states = options.states ?? [];
  const terminations: string[] = [];
  const runtime = new LocalTmuxRuntime({
    executor,
    sessionIncarnationSource: () => SESSION_INCARNATION,
    sourceEnvironment: {
      NODE_ENV: "test",
      PATH: "/safe/bin",
      HOME: "/safe/home",
      SHELL: "/bin/bash",
      LANG: "C.UTF-8",
      LC_ALL: "unsafe\nlocale",
      TERMINALX_JWT_SECRET: "jwt-secret",
      TERMINALX_ADMIN_PASSWORD: "admin-secret",
      TERMINALX_TELEGRAM_BOT_TOKEN: "telegram-secret",
      OP_CONNECT_TOKEN: "one-password-secret",
      AWS_SECRET_ACCESS_KEY: "cloud-secret",
    },
    fenceCallbacks: {
      updateWriteState(update) {
        states.push(update);
        options.log?.push(`state:${update.state}:${update.runtimeAuthorizationGeneration}`);
      },
      async terminateCanonicalPtys(input) {
        options.terminationInputs?.push(input);
        terminations.push(`${input.reason}:${input.tmuxName}`);
        options.log?.push(`terminate:${input.reason}`);
      },
      async runtimeEnsureState(input) {
        options.ensureInputs?.push(input);
        return typeof options.ensureState === "function"
          ? options.ensureState()
          : (options.ensureState ?? "pending");
      },
      async isCurrentRuntimeBinding(input) {
        options.bindingInputs?.push(input);
        return options.currentBinding ?? true;
      },
    },
  });
  return { runtime, states, terminations };
}

describe("LocalTmuxRuntime", () => {
  it.each([
    "runtime.session.ensure",
    "runtime.authorization.fence",
    "runtime.session.retire",
  ] as const)("fails closed before any local effect for hosted delivery %s", async (kind) => {
    const executor = new ScriptedExecutor([]);
    const states: RuntimeWriteStateUpdate[] = [];
    const { runtime, terminations } = runtimeWith(executor, { states });

    await expect(runtime.apply(hostedDelivery(kind))).rejects.toMatchObject({
      code: "runtime_invalid_state",
      retryable: false,
    });

    expect(executor.requests).toEqual([]);
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });

  it("creates and marks an exact canonical session on a dedicated scrubbed tmux server", async () => {
    const executor = new ScriptedExecutor([
      failure("no server running on /tmp/tmux"),
      success(),
      success(marker()),
      success(sessionLine()),
      success(sessionLine()),
    ]);
    const { runtime, states } = runtimeWith(executor);

    await runtime.apply(delivery("runtime.session.ensure"));

    expect(states).toEqual([
      {
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 1,
        state: "active",
      },
    ]);
    expect(executor.requests).toHaveLength(5);
    const socketName = getCanonicalTmuxSocketName(SESSION_ID, {});
    for (const request of executor.requests) {
      expect(request.args.slice(0, 4)).toEqual(["-L", socketName, "-f", "/dev/null"]);
      expect(request.env).not.toHaveProperty("TERMINALX_JWT_SECRET");
      expect(request.env).not.toHaveProperty("TERMINALX_ADMIN_PASSWORD");
      expect(request.env).not.toHaveProperty("TERMINALX_TELEGRAM_BOT_TOKEN");
      expect(request.env).not.toHaveProperty("OP_CONNECT_TOKEN");
      expect(request.env).not.toHaveProperty("AWS_SECRET_ACCESS_KEY");
      expect(request.env).not.toHaveProperty("LC_ALL");
      expect(JSON.stringify(request.args)).not.toContain("secret");
    }
    const create = executor.requests[1]!;
    expect(create.args.slice(4, 11)).toEqual([
      "start-server",
      ";",
      "set-option",
      "-g",
      "@terminalx_runtime_server",
      `v2:${SESSION_ID}:${SESSION_INCARNATION}`,
      ";",
    ]);
    expect(create.args).toContain("new-session");
    expect(create.args).toContain("-E");
    expect(create.args).toContain("@terminalx_runtime_server");
    expect(create.args).toContain("@terminalx_session_id");
    expect(create.args).toContain("@terminalx_session_incarnation");
    expect(create.args).toContain("@terminalx_runtime_authorization_generation");
    expect(create.args).toContain("=canonical-agent:");
    expect(create.args).toEqual(expect.arrayContaining(["prefix", "None", "prefix2", "None"]));
  });

  it("removes an ensure that becomes stale after a concurrent emergency retirement", async () => {
    let active = false;
    let current = true;
    let releaseCreate: (() => void) | undefined;
    let markCreateStarted: (() => void) | undefined;
    const createStarted = new Promise<void>((resolve) => {
      markCreateStarted = resolve;
    });
    const createReleased = new Promise<void>((resolve) => {
      releaseCreate = resolve;
    });
    const requests: ExactCommandRequest[] = [];
    const executor: ExactCommandExecutor = {
      async execute(request) {
        requests.push(request);
        switch (operation(request.args)) {
          case "show-options":
            return active ? success(marker()) : failure("no server running on /tmp/tmux");
          case "start-server":
            markCreateStarted?.();
            await createReleased;
            active = true;
            return success();
          case "list-sessions":
            return active ? success(sessionLine()) : failure("no server running on /tmp/tmux");
          case "detach-client":
            return success();
          case "kill-session":
            active = false;
            return success();
          default:
            throw new Error(`Unexpected tmux operation: ${operation(request.args)}`);
        }
      },
    };
    const { runtime, states, terminations } = runtimeWith(executor, {
      ensureState: () => (current ? "pending" : "stale"),
    });

    const applying = runtime.apply(delivery("runtime.session.ensure"));
    await createStarted;
    current = false;
    releaseCreate?.();

    await expect(applying).rejects.toMatchObject({
      code: "runtime_invalid_state",
      retryable: false,
    });
    expect(active).toBe(false);
    expect(requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "start-server",
      "show-options",
      "list-sessions",
      "list-sessions",
      "list-sessions",
      "detach-client",
      "list-sessions",
      "list-sessions",
      "kill-session",
      "list-sessions",
    ]);
    expect(states.at(-1)).toEqual({
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: 1,
      state: "retired",
    });
    expect(terminations).toEqual(["retire:canonical-agent"]);
  });

  it("preserves an exact Session already enforced by a newer ensure attempt", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine()),
      success(sessionLine()),
    ]);
    let inspection = 0;
    const { runtime, states, terminations } = runtimeWith(executor, {
      ensureState: () => (++inspection === 1 ? "pending" : "enforced"),
    });

    await expect(runtime.apply(delivery("runtime.session.ensure"))).resolves.toBeUndefined();

    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
      "list-sessions",
    ]);
    expect(executor.requests.some((request) => operation(request.args) === "kill-session")).toBe(
      false
    );
    expect(terminations).toEqual([]);
    expect(states.at(-1)).toEqual({
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: 1,
      state: "active",
    });
  });

  it("is idempotent for its exact binding and refuses an unmanaged name collision", async () => {
    const exactExecutor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine()),
      success(sessionLine()),
    ]);
    const exact = runtimeWith(exactExecutor);
    await exact.runtime.apply(delivery("runtime.session.ensure"));
    expect(exactExecutor.requests.some((request) => request.args.includes("new-session"))).toBe(
      false
    );

    const collisionExecutor = new ScriptedExecutor([
      success(marker()),
      success(`canonical-agent\t\t\t\n`),
    ]);
    const collision = runtimeWith(collisionExecutor);
    await expect(collision.runtime.apply(delivery("runtime.session.ensure"))).rejects.toMatchObject(
      {
        code: "runtime_conflict",
        retryable: false,
      }
    );
    expect(collisionExecutor.requests.some((request) => request.args.includes("set-option"))).toBe(
      false
    );
  });

  it("never re-enables writes when an exact ensure is replaced before its final boundary", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("canonical-agent", 1, SESSION_ID, "$1")),
      success(sessionLine("canonical-agent", 1, SESSION_ID, "$2")),
    ]);
    const { runtime, states } = runtimeWith(executor);

    await expect(runtime.apply(delivery("runtime.session.ensure"))).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });
    expect(states).toEqual([]);
  });

  it("reconciles a marker-before-effect crash by creating the still-current exact binding", async () => {
    const executor = new ScriptedExecutor([
      failure("no server running on /tmp/tmux"),
      failure("no server running on /tmp/tmux"),
      success(),
      success(marker()),
      success(sessionLine()),
      success(sessionLine()),
    ]);
    const { runtime, states } = runtimeWith(executor);
    const ambiguous = delivery(
      "runtime.session.ensure",
      1,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );

    await expect(runtime.reconcile(ambiguous)).resolves.toBeUndefined();

    expect(
      executor.requests.filter((request) => request.args.includes("new-session"))
    ).toHaveLength(1);
    expect(states).toEqual([
      {
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 1,
        state: "active",
      },
    ]);
  });

  it("reconciles a marker-before-effect crash as complete when the absent binding is stale", async () => {
    const executor = new ScriptedExecutor([failure("no server running on /tmp/tmux")]);
    const { runtime, states, terminations } = runtimeWith(executor, { ensureState: "stale" });
    const ambiguous = delivery(
      "runtime.session.ensure",
      1,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );

    await expect(runtime.reconcile(ambiguous)).resolves.toBeUndefined();

    expect(executor.requests.map((request) => operation(request.args))).toEqual(["show-options"]);
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });

  it("finishes reconciliation when an exact ensure becomes stale during observation", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine()),
      success(sessionLine()),
      success(sessionLine()),
      success(),
      success(sessionLine()),
      success(sessionLine()),
      success(),
      failure("no server running on /tmp/tmux"),
    ]);
    let inspection = 0;
    const { runtime, states, terminations } = runtimeWith(executor, {
      ensureState: () => (++inspection === 1 ? "pending" : "stale"),
    });
    const ambiguous = delivery(
      "runtime.session.ensure",
      1,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );

    await expect(runtime.reconcile(ambiguous)).resolves.toBeUndefined();

    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
      "list-sessions",
      "list-sessions",
      "detach-client",
      "list-sessions",
      "list-sessions",
      "kill-session",
      "list-sessions",
    ]);
    expect(states.at(-1)).toEqual({
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: 1,
      state: "retired",
    });
    expect(terminations).toEqual(["retire:canonical-agent"]);
  });

  it("fails closed when a live same-generation ref replacement appears during stale ensure cleanup", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("canonical-agent", 1, SESSION_ID, "$1")),
      success(sessionLine("canonical-agent", 1, SESSION_ID, "$2")),
    ]);
    const { runtime, states, terminations } = runtimeWith(executor, { ensureState: "stale" });
    const ambiguous = delivery(
      "runtime.session.ensure",
      1,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );

    await expect(runtime.reconcile(ambiguous)).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });
    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
      "list-sessions",
    ]);
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });

  it("fails closed on a same-generation name conflict during stale ensure reconciliation", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("replacement-name")),
    ]);
    const { runtime, states, terminations } = runtimeWith(executor, { ensureState: "stale" });
    const ambiguous = delivery(
      "runtime.session.ensure",
      1,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );

    await expect(runtime.reconcile(ambiguous)).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });
    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
    ]);
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });

  it("observes but never mutates a strictly newer ensure replacement", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("replacement-name", 2, SESSION_ID, "$2")),
    ]);
    const { runtime, states, terminations } = runtimeWith(executor, { ensureState: "stale" });
    const ambiguous = delivery(
      "runtime.session.ensure",
      1,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );

    await expect(runtime.reconcile(ambiguous)).resolves.toBeUndefined();
    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
    ]);
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });

  it("fences writes before updating tmux and terminating canonical PTYs", async () => {
    const log: string[] = [];
    const executor = new ScriptedExecutor(
      [
        success(marker()),
        success(sessionLine()),
        success(sessionLine()),
        success(),
        success(sessionLine("canonical-agent", 2)),
        success(sessionLine("canonical-agent", 2)),
        success(),
        success(sessionLine("canonical-agent", 2)),
        success(sessionLine("canonical-agent", 2)),
      ],
      log
    );
    const { runtime, states, terminations } = runtimeWith(executor, { log });

    await runtime.apply(delivery("runtime.authorization.fence", 2));

    expect(log[0]).toBe("state:fenced:2");
    expect(log).toEqual([
      "state:fenced:2",
      "exec:show-options",
      "exec:list-sessions",
      "exec:list-sessions",
      "exec:set-option",
      "exec:list-sessions",
      "exec:list-sessions",
      "exec:detach-client",
      "exec:list-sessions",
      "terminate:authorization-fence",
      "exec:list-sessions",
    ]);
    expect(states.at(-1)?.state).toBe("fenced");
    expect(terminations).toEqual(["authorization-fence:canonical-agent"]);
    const guardedEffects = executor.requests.filter((request) =>
      ["set-option", "detach-client"].includes(operation(request.args))
    );
    expect(guardedEffects).not.toHaveLength(0);
    for (const request of guardedEffects) {
      expect(request.args[4]).toBe("if-shell");
      expect(request.args[8]).toContain("@terminalx_session_incarnation");
      expect(request.args[8]).toContain(SESSION_INCARNATION);
    }
  });

  it("fails closed when a live same-generation ref replacement appears during fencing", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("canonical-agent", 1, SESSION_ID, "$1")),
      success(sessionLine("canonical-agent", 1, SESSION_ID, "$2")),
    ]);
    const { runtime, states, terminations } = runtimeWith(executor);

    await expect(runtime.apply(delivery("runtime.authorization.fence", 2))).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });
    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
      "list-sessions",
    ]);
    expect(states).toEqual([
      {
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 2,
        state: "fenced",
      },
    ]);
    expect(terminations).toEqual([]);
  });

  it("rejects restarted-server ref reuse with a different per-session incarnation", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("canonical-agent", 1, SESSION_ID, "$1", SESSION_INCARNATION)),
      success(sessionLine("canonical-agent", 1, SESSION_ID, "$1", REPLACEMENT_SESSION_INCARNATION)),
    ]);
    const { runtime, terminations } = runtimeWith(executor);

    await expect(runtime.apply(delivery("runtime.authorization.fence", 2))).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });
    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
      "list-sessions",
    ]);
    expect(terminations).toEqual([]);
  });

  it("rejects restarted-server ref reuse after the guarded fence command", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("canonical-agent", 1, SESSION_ID, "$1", SESSION_INCARNATION)),
      success(sessionLine("canonical-agent", 1, SESSION_ID, "$1", SESSION_INCARNATION)),
      // A false guarded predicate is a successful tmux command. The following
      // observation must still reject a restarted server that reused `$1` and
      // the same durable generation with a different incarnation.
      success(),
      success(sessionLine("canonical-agent", 2, SESSION_ID, "$1", REPLACEMENT_SESSION_INCARNATION)),
    ]);
    const { runtime, terminations } = runtimeWith(executor);

    await expect(runtime.apply(delivery("runtime.authorization.fence", 2))).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });
    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
      "list-sessions",
      "set-option",
      "list-sessions",
    ]);
    expect(terminations).toEqual([]);
  });

  it("does not let stale work downgrade an in-memory fence", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine()),
      success(sessionLine()),
      success(),
      success(sessionLine("canonical-agent", 2)),
      success(sessionLine("canonical-agent", 2)),
      success(),
      success(sessionLine("canonical-agent", 2)),
      success(sessionLine("canonical-agent", 2)),
      success(marker()),
      success(sessionLine("canonical-agent", 2)),
    ]);
    const states: RuntimeWriteStateUpdate[] = [];
    const { runtime } = runtimeWith(executor, { states });

    await runtime.apply(delivery("runtime.authorization.fence", 2));
    await runtime.apply(delivery("runtime.session.ensure", 1));

    expect(states).toEqual([
      {
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 2,
        state: "fenced",
      },
    ]);
  });

  it("does not fence, detach, or terminate a newer replacement while reconciling", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("replacement-name", 3, SESSION_ID, "$2")),
    ]);
    const { runtime, states, terminations } = runtimeWith(executor);
    const ambiguous = delivery(
      "runtime.authorization.fence",
      2,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );

    await expect(runtime.reconcile(ambiguous)).resolves.toBeUndefined();
    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
    ]);
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });

  it("fails closed when a newer replacement remains live after fencing selected an exact target", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("canonical-agent", 2, SESSION_ID, "$1")),
      success(sessionLine("canonical-agent", 2, SESSION_ID, "$1")),
      success(),
      success(
        sessionLine("replacement-name", 3, SESSION_ID, "$2", REPLACEMENT_SESSION_INCARNATION)
      ),
    ]);
    const { runtime, states, terminations } = runtimeWith(executor);
    const ambiguous = delivery(
      "runtime.authorization.fence",
      2,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );

    await expect(runtime.reconcile(ambiguous)).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });
    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
      "list-sessions",
      "set-option",
      "list-sessions",
    ]);
    expect(states.at(-1)).toEqual({
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: 2,
      state: "fenced",
    });
    expect(terminations).toEqual([]);
  });

  it("finishes an exact partially applied fence idempotently during reconciliation", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("canonical-agent", 2)),
      success(sessionLine("canonical-agent", 2)),
      success(),
      success(sessionLine("canonical-agent", 2)),
      success(sessionLine("canonical-agent", 2)),
      success(),
      success(sessionLine("canonical-agent", 2)),
      success(sessionLine("canonical-agent", 2)),
    ]);
    const { runtime, states, terminations } = runtimeWith(executor);
    const ambiguous = delivery(
      "runtime.authorization.fence",
      2,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );

    await expect(runtime.reconcile(ambiguous)).resolves.toBeUndefined();
    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
      "list-sessions",
      "set-option",
      "list-sessions",
      "list-sessions",
      "detach-client",
      "list-sessions",
      "list-sessions",
    ]);
    expect(states).toEqual([
      {
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 2,
        state: "fenced",
      },
    ]);
    expect(terminations).toEqual(["authorization-fence:canonical-agent"]);
  });

  it("fails a stale emergency-retire binding before any tmux or PTY effect", async () => {
    const executor = new ScriptedExecutor([]);
    const { runtime, states, terminations } = runtimeWith(executor, {
      currentBinding: false,
    });
    await expect(runtime.apply(emergencyRetireDelivery())).rejects.toMatchObject({
      code: "runtime_invalid_state",
      retryable: false,
    });
    expect(executor.requests).toEqual([]);
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });

  it("keeps non-emergency retirement closed until it carries an exact Runtime identity", async () => {
    const executor = new ScriptedExecutor([]);
    const bindingInputs: unknown[] = [];
    const { runtime, states, terminations } = runtimeWith(executor, { bindingInputs });

    const malformed = {
      ...delivery("runtime.session.retire", 2),
      payload: { sessionId: SESSION_ID, runtimeAuthorizationGeneration: 2 },
    } as unknown as RuntimeOutboxDelivery;
    await expect(runtime.apply(malformed)).rejects.toMatchObject({
      code: "runtime_invalid_state",
      retryable: false,
    });

    expect(bindingInputs).toEqual([]);
    expect(executor.requests).toEqual([]);
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });

  it("emergency retirement kills the exact bound Session despite a stale subordinate generation", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine()),
      success(sessionLine()),
      success(),
      success(sessionLine()),
      success(sessionLine()),
      success(),
      failure("no server running on /tmp/tmux"),
    ]);
    const bindingInputs: unknown[] = [];
    const terminationInputs: CanonicalPtyTermination[] = [];
    const { runtime, states } = runtimeWith(executor, { bindingInputs, terminationInputs });
    await runtime.apply(emergencyRetireDelivery(2));

    expect(bindingInputs).toHaveLength(4);
    for (const input of bindingInputs) {
      expect(input).toEqual({
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 2,
        emergencyStop: {
          agentRunId: "run-one",
          runtimeAssignmentId: "assignment-one",
          runtimeAssignmentGeneration: 1,
          sandboxId: "sandbox-one",
          sandboxGeneration: 1,
        },
      });
    }
    expect(states.at(-1)).toEqual({
      sessionId: SESSION_ID,
      runtimeAuthorizationGeneration: 2,
      state: "retired",
    });
    expect(
      guardedCommand(
        executor.requests.find((request) => operation(request.args) === "kill-session")?.args ?? []
      )
    ).toBe("kill-session -t $1");
    expect(terminationInputs).toEqual([
      expect.objectContaining({
        tmuxSessionRef: "$1",
        tmuxSessionIncarnation: SESSION_INCARNATION,
        tmuxName: "canonical-agent",
      }),
    ]);
  });

  it("refuses to retire a newer replacement during reconciliation", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine("replacement-name", 3, SESSION_ID, "$2")),
    ]);
    const { runtime, states, terminations } = runtimeWith(executor);
    const ambiguous = {
      ...emergencyRetireDelivery(2),
      dispatchMode: "reconcile" as const,
    };

    await expect(runtime.reconcile(ambiguous)).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });
    expect(executor.requests.map((request) => operation(request.args))).toEqual([
      "show-options",
      "list-sessions",
    ]);
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });

  it("stops a destructive retirement when the immutable tmux binding is replaced mid-flight", async () => {
    let listCount = 0;
    const requests: ExactCommandRequest[] = [];
    const executor: ExactCommandExecutor = {
      async execute(request) {
        requests.push(request);
        switch (operation(request.args)) {
          case "show-options":
            return success(marker());
          case "list-sessions":
            listCount += 1;
            return success(
              listCount < 4
                ? sessionLine("canonical-agent", 1, SESSION_ID, "$1")
                : sessionLine("replacement-agent", 2, SESSION_ID, "$2")
            );
          case "detach-client":
            return success();
          case "kill-session":
            throw new Error("replacement must never be killed");
          default:
            throw new Error(`Unexpected tmux operation: ${operation(request.args)}`);
        }
      },
    };
    const terminationInputs: CanonicalPtyTermination[] = [];
    const { runtime } = runtimeWith(executor, { terminationInputs });

    await expect(runtime.apply(emergencyRetireDelivery())).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });

    const detach = requests.find((request) => operation(request.args) === "detach-client");
    expect(guardedCommand(detach?.args ?? [])).toBe("detach-client -s $1");
    expect(requests.some((request) => operation(request.args) === "kill-session")).toBe(false);
    expect(requests.some((request) => request.args.includes("=canonical-agent:"))).toBe(false);
    expect(terminationInputs).toEqual([
      expect.objectContaining({
        tmuxSessionRef: "$1",
        tmuxSessionIncarnation: SESSION_INCARNATION,
        tmuxName: "canonical-agent",
      }),
    ]);
  });

  it("honors cancellation before and during every exact tmux executor boundary", async () => {
    const preAborted = new AbortController();
    preAborted.abort();
    const untouched = new ScriptedExecutor([]);
    const before = runtimeWith(untouched);
    await expect(
      before.runtime.apply(delivery("runtime.session.ensure"), preAborted.signal)
    ).rejects.toMatchObject({ code: "runtime_timeout", retryable: true });
    expect(untouched.requests).toEqual([]);
    expect(before.states).toEqual([]);

    const controller = new AbortController();
    let observedSignal: AbortSignal | undefined;
    let releaseStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      releaseStarted = resolve;
    });
    const blocking: ExactCommandExecutor = {
      execute(request) {
        observedSignal = request.signal;
        releaseStarted?.();
        return new Promise((resolve) => {
          request.signal.addEventListener(
            "abort",
            () => resolve({ ok: false, failure: "aborted", stdout: "", stderr: "" }),
            { once: true }
          );
        });
      },
    };
    const during = runtimeWith(blocking);
    const applying = during.runtime.apply(delivery("runtime.session.ensure"), controller.signal);
    await started;
    controller.abort();

    await expect(applying).rejects.toMatchObject({ code: "runtime_timeout", retryable: true });
    expect(observedSignal?.aborted).toBe(true);
    expect(during.states).toEqual([]);
  });

  it("rejects unbounded command timeouts", () => {
    expect(
      () =>
        new LocalTmuxRuntime({
          commandTimeoutMs: 0,
          fenceCallbacks: {
            updateWriteState() {},
            async terminateCanonicalPtys() {},
            async runtimeEnsureState() {
              return "pending";
            },
            async isCurrentRuntimeBinding() {
              return true;
            },
          },
        })
    ).toThrow(RuntimeEffectError);
  });

  it("derives a distinct validated canonical socket for every Team Session", () => {
    const first = getCanonicalTmuxSocketName(SESSION_ID, {});
    const second = getCanonicalTmuxSocketName(SECOND_SESSION_ID, {});
    expect(first).toMatch(/^terminalx-multi-[a-f0-9]{48}$/);
    expect(first).toHaveLength(64);
    expect(second).not.toBe(first);
    expect(getCanonicalTmuxSocketName(SESSION_ID, {})).toBe(first);
    expect(
      getCanonicalTmuxSocketName(SESSION_ID, {
        [CANONICAL_TMUX_SOCKET_NAME_ENV]: "team-runtime",
      })
    ).not.toBe(first);
    expect(() =>
      getCanonicalTmuxSocketName(SESSION_ID, {
        [CANONICAL_TMUX_SOCKET_NAME_ENV]: "bad\nname",
      })
    ).toThrow(RuntimeEffectError);
    expect(() => getCanonicalTmuxSocketName("not-a-session", {})).toThrow(RuntimeEffectError);
    expect(() => getCanonicalTmuxSocketName("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", {})).toThrow(
      RuntimeEffectError
    );
    expect(canonicalTmuxTarget("canonical-agent")).toBe("=canonical-agent:");
  });

  it("runs two canonical Team Sessions on isolated tmux sockets", async () => {
    const executor = new ScriptedExecutor([
      failure("no server running on /tmp/tmux"),
      success(),
      success(marker(SESSION_ID)),
      success(sessionLine()),
      success(sessionLine()),
      failure("no server running on /tmp/tmux"),
      success(),
      success(marker(SECOND_SESSION_ID)),
      success(sessionLine("canonical-agent-b", 1, SECOND_SESSION_ID)),
      success(sessionLine("canonical-agent-b", 1, SECOND_SESSION_ID)),
    ]);
    const { runtime } = runtimeWith(executor);

    await runtime.apply(delivery("runtime.session.ensure"));
    await runtime.apply(
      delivery("runtime.session.ensure", 1, 1, SECOND_SESSION_ID, "canonical-agent-b")
    );

    const firstSocket = getCanonicalTmuxSocketName(SESSION_ID, {});
    const secondSocket = getCanonicalTmuxSocketName(SECOND_SESSION_ID, {});
    expect(new Set(executor.requests.slice(0, 5).map((request) => request.args[1]))).toEqual(
      new Set([firstSocket])
    );
    expect(new Set(executor.requests.slice(5).map((request) => request.args[1]))).toEqual(
      new Set([secondSocket])
    );
    expect(firstSocket).not.toBe(secondSocket);
    expect(
      executor.requests.slice(0, 5).every((request) => !request.args.includes("canonical-agent-b"))
    ).toBe(true);
  });

  it("fails closed when a per-session socket contains any foreign session", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(sessionLine() + sessionLine("foreign", 1, SECOND_SESSION_ID, "$2")),
    ]);
    const { runtime, states } = runtimeWith(executor);

    await expect(runtime.apply(delivery("runtime.session.ensure"))).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });
    expect(executor.requests).toHaveLength(2);
    expect(states).toEqual([]);
  });

  it("records a retired fence after a verified binding is already absent", async () => {
    const executor = new ScriptedExecutor([failure("no server running on /tmp/tmux")]);
    const { runtime, states, terminations } = runtimeWith(executor);

    await runtime.apply(emergencyRetireDelivery(2));

    expect(states).toEqual([
      {
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 2,
        state: "retired",
      },
    ]);
    expect(terminations).toEqual([]);
  });

  it("does not treat a permission-denied socket connection as completed retirement", async () => {
    const executor = new ScriptedExecutor([
      failure("error connecting to /tmp/tmux/terminalx (Permission denied)"),
    ]);
    const { runtime, states, terminations } = runtimeWith(executor);

    await expect(runtime.apply(emergencyRetireDelivery(2))).rejects.toMatchObject({
      code: "runtime_permission_denied",
      retryable: false,
    });
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });
});

class FakeKernel implements RuntimeOutboxKernel {
  readonly commands: SessionCommand[] = [];
  readonly claimOptions: RuntimeOutboxClaimOptions[] = [];
  readonly interlocks: Array<Parameters<RuntimeOutboxKernel["markRuntimeOutboxDispatch"]>[0]> = [];
  readonly renewals: Array<Parameters<RuntimeOutboxKernel["renewRuntimeOutboxLease"]>[0]> = [];
  claimCount = 0;

  constructor(
    private readonly batches: RuntimeOutboxDelivery[][],
    private readonly renewer?: (
      options: Parameters<RuntimeOutboxKernel["renewRuntimeOutboxLease"]>[0],
      renewalCount: number
    ) =>
      | Awaited<ReturnType<RuntimeOutboxKernel["renewRuntimeOutboxLease"]>>
      | Promise<Awaited<ReturnType<RuntimeOutboxKernel["renewRuntimeOutboxLease"]>>>
  ) {}

  async claimRuntimeOutbox(options: RuntimeOutboxClaimOptions): Promise<RuntimeOutboxDelivery[]> {
    this.claimCount += 1;
    this.claimOptions.push(options);
    return this.batches.shift() ?? [];
  }

  async renewRuntimeOutboxLease(
    options: Parameters<RuntimeOutboxKernel["renewRuntimeOutboxLease"]>[0]
  ) {
    this.renewals.push(options);
    if (this.renewer) return this.renewer(options, this.renewals.length);
    return {
      leaseExpiresAtMs: Math.max(
        options.expectedLeaseExpiresAtMs,
        2_000_000_000_000 + options.leaseDurationMs
      ),
    };
  }

  async markRuntimeOutboxDispatch(
    options: Parameters<RuntimeOutboxKernel["markRuntimeOutboxDispatch"]>[0]
  ): Promise<void> {
    this.interlocks.push(options);
  }

  async dispatch(command: SessionCommand): Promise<CommandResult> {
    this.commands.push(command);
    return {
      accepted: true,
      acceptedSequence: this.commands.length,
      commandType: command.type,
      replayed: false,
      data: {},
      events: [],
    };
  }
}

describe("RuntimeOutboxWorker", () => {
  it("accepts hosted payloads and detaches their nested binding before the dispatch interlock", async () => {
    const job = hostedDelivery("runtime.session.ensure");
    if (job.kind !== "runtime.session.ensure" || job.payload.runtimeKind !== "daytona") {
      throw new Error("Expected hosted ensure delivery");
    }
    const originalSandboxId = job.payload.binding.sandboxId;
    let applied: RuntimeOutboxDelivery | undefined;
    const kernel = new FakeKernel([[job]], (options) => {
      (job.payload.binding as { sandboxId: string }).sandboxId = "attacker-selected-sandbox";
      return {
        leaseExpiresAtMs: Math.max(
          options.expectedLeaseExpiresAtMs,
          2_000_000_000_000 + options.leaseDurationMs
        ),
      };
    });
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply(input) {
          applied = input;
        },
        async reconcile() {
          throw new Error("unexpected reconcile");
        },
      },
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
    });

    await expect(worker.runOnce()).resolves.toMatchObject({ acknowledged: 1 });

    expect(applied?.kind).toBe("runtime.session.ensure");
    if (applied?.kind !== "runtime.session.ensure" || applied.payload.runtimeKind !== "daytona") {
      throw new Error("Expected detached hosted ensure delivery");
    }
    expect(applied.payload.binding.sandboxId).toBe(originalSandboxId);
    expect(Object.isFrozen(applied.payload.binding)).toBe(true);
  });

  it("claims leased work and acknowledges the exact attempt", async () => {
    const job = delivery("runtime.session.ensure", 1, 3);
    const kernel = new FakeKernel([[job]]);
    const runtime: RuntimeOutboxApplier = {
      apply: async () => {},
      reconcile: async () => {},
    };
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime,
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
    });

    await expect(worker.runOnce()).resolves.toEqual({
      claimed: 1,
      acknowledged: 1,
      retried: 0,
      failedPermanently: 0,
    });
    expect(kernel.commands).toEqual([
      expect.objectContaining({
        type: "runtime.outbox.acknowledge",
        outboxId: job.outboxId,
        expectedAttempt: 3,
        expectedLeaseExpiresAtMs: job.leaseExpiresAtMs,
        workerId: "runtime-worker-1",
      }),
    ]);
    expect(kernel.interlocks).toEqual([
      {
        outboxId: job.outboxId,
        workerId: "runtime-worker-1",
        expectedAttempt: 3,
        expectedLeaseExpiresAtMs: job.leaseExpiresAtMs,
      },
    ]);
    expect(kernel.claimOptions).toEqual([
      {
        workerId: "runtime-worker-1",
        limit: 1,
        leaseDurationMs: 30_000,
      },
    ]);
    expect(worker.health()).toEqual({
      lastSuccessAtMs: 2_000_000_000_000,
      lastErrorAtMs: null,
      activeCycleStartedAtMs: null,
      failureSinceSuccess: false,
    });
  });

  it("does not misreport an acknowledgement transport failure as an effect failure", async () => {
    const job = delivery("runtime.session.ensure");
    const commands: SessionCommand[] = [];
    const kernel: RuntimeOutboxKernel = {
      async claimRuntimeOutbox() {
        return [job];
      },
      async renewRuntimeOutboxLease(options) {
        return { leaseExpiresAtMs: options.expectedLeaseExpiresAtMs };
      },
      async markRuntimeOutboxDispatch() {},
      async dispatch(command) {
        commands.push(command);
        throw new Error("kernel unavailable");
      },
    };
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: { apply: async () => {}, reconcile: async () => {} },
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
    });

    await expect(worker.runOnce()).rejects.toThrow("kernel unavailable");
    expect(commands).toHaveLength(1);
    expect(commands[0]).toMatchObject({ type: "runtime.outbox.acknowledge" });
    expect(worker.health()).toEqual({
      lastSuccessAtMs: null,
      lastErrorAtMs: 2_000_000_000_000,
      activeCycleStartedAtMs: null,
      failureSinceSuccess: true,
    });
  });

  it("retries transient failures but sends permanent conflicts to quarantine", async () => {
    const transient = delivery("runtime.session.ensure", 1, 1);
    const conflict = delivery(
      "runtime.session.ensure",
      1,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );
    let calls = 0;
    const fail = async () => {
      calls += 1;
      throw calls === 1
        ? new RuntimeEffectError("runtime_timeout", true)
        : new RuntimeEffectError("runtime_conflict", false);
    };
    const runtime: RuntimeOutboxApplier = {
      apply: fail,
      reconcile: fail,
    };
    const kernel = new FakeKernel([[transient], [conflict]]);
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime,
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
    });

    await expect(worker.runOnce()).resolves.toMatchObject({ retried: 1 });
    await expect(worker.runOnce()).resolves.toMatchObject({ failedPermanently: 1 });
    expect(kernel.commands).toEqual([
      expect.objectContaining({
        type: "runtime.outbox.fail",
        errorCode: "runtime_timeout",
        retryable: true,
        expectedAttempt: 1,
      }),
      expect.objectContaining({
        type: "runtime.outbox.fail",
        errorCode: "runtime_conflict",
        retryable: false,
        expectedAttempt: 2,
      }),
    ]);
  });

  it("caps transient attempts and never puts raw errors in kernel commands", async () => {
    const kernel = new FakeKernel([
      [delivery("runtime.session.ensure", 1, 2, SESSION_ID, "canonical-agent", "reconcile")],
    ]);
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply() {
          throw new Error("unexpected apply");
        },
        async reconcile() {
          throw new Error("SECRET raw adapter failure");
        },
      },
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
      maxTransientAttempts: 2,
    });

    await worker.runOnce();

    expect(kernel.commands[0]).toEqual(
      expect.objectContaining({
        type: "runtime.outbox.fail",
        errorCode: "runtime_internal",
        retryable: false,
      })
    );
    expect(JSON.stringify(kernel.commands)).not.toContain("SECRET");
  });

  it("forces a fresh marked failure through reconciliation despite a permanent error and exhausted budget", async () => {
    const job = delivery("runtime.session.ensure", 1, 100);
    const kernel = new FakeKernel([[job]]);
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply() {
          throw new RuntimeEffectError("runtime_conflict", false);
        },
        async reconcile() {
          throw new Error("unexpected reconcile");
        },
      },
      workerId: "runtime-worker-1",
      maxTransientAttempts: 1,
      clock: () => 2_000_000_000_000,
    });

    await expect(worker.runOnce()).resolves.toMatchObject({
      retried: 1,
      failedPermanently: 0,
    });
    expect(kernel.commands).toEqual([
      expect.objectContaining({
        type: "runtime.outbox.fail",
        retryable: true,
        errorCode: "runtime_conflict",
      }),
    ]);
  });

  it("snapshots lease identity before an adapter can mutate its delivery", async () => {
    const job = delivery("runtime.session.ensure", 1, 7);
    const originalOutboxId = job.outboxId;
    const originalAttempt = job.attempts;
    const kernel = new FakeKernel([[job]]);
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply(input) {
          input.outboxId = "attacker-selected-outbox";
          input.attempts = 9_999;
          input.dispatchMode = "reconcile";
          throw new RuntimeEffectError("runtime_conflict", false);
        },
        async reconcile() {},
      },
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
    });

    await worker.runOnce();

    expect(kernel.interlocks).toEqual([
      {
        outboxId: originalOutboxId,
        workerId: "runtime-worker-1",
        expectedAttempt: originalAttempt,
        expectedLeaseExpiresAtMs: job.leaseExpiresAtMs,
      },
    ]);
    expect(kernel.commands).toEqual([
      expect.objectContaining({
        type: "runtime.outbox.fail",
        outboxId: originalOutboxId,
        expectedAttempt: originalAttempt,
        retryable: true,
      }),
    ]);
  });

  it("rejects hostile delivery accessors and proxies before renewing or marking a lease", async () => {
    let getterCalls = 0;
    const getterClaim = { ...delivery("runtime.session.ensure") };
    Object.defineProperty(getterClaim, "dispatchMode", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "apply";
      },
    });
    let proxyTrapCalls = 0;
    const proxyClaim = new Proxy(delivery("runtime.session.ensure"), {
      ownKeys() {
        proxyTrapCalls += 1;
        throw new Error("hostile ownKeys trap");
      },
    });

    for (const unsafeClaim of [getterClaim, proxyClaim]) {
      const kernel = new FakeKernel([[unsafeClaim as RuntimeOutboxDelivery]]);
      let adapterCalls = 0;
      const worker = new RuntimeOutboxWorker({
        kernel,
        runtime: {
          async apply() {
            adapterCalls += 1;
          },
          async reconcile() {
            adapterCalls += 1;
          },
        },
        workerId: "runtime-worker-1",
        clock: () => 2_000_000_000_000,
      });

      await expect(worker.runOnce()).rejects.toMatchObject({
        code: "runtime_invalid_state",
        retryable: false,
      });
      expect(kernel.renewals).toEqual([]);
      expect(kernel.interlocks).toEqual([]);
      expect(kernel.commands).toEqual([]);
      expect(adapterCalls).toBe(0);
    }
    expect(getterCalls).toBe(0);
    expect(proxyTrapCalls).toBe(0);
  });

  it("uses the kernel's exact renewed expiry when its clock advances during renewal", async () => {
    let now = 2_000_000_000_000;
    const job = delivery("runtime.session.ensure");
    const kernel = new FakeKernel([[job]], (options) => {
      now += 1;
      return {
        leaseExpiresAtMs: Math.max(options.expectedLeaseExpiresAtMs, now + options.leaseDurationMs),
      };
    });
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: { apply: async () => {}, reconcile: async () => {} },
      workerId: "runtime-worker-1",
      clock: () => now,
    });

    await expect(worker.runOnce()).resolves.toMatchObject({ acknowledged: 1 });
    const exactRenewedExpiry = job.leaseExpiresAtMs + 1;
    expect(kernel.interlocks[0]?.expectedLeaseExpiresAtMs).toBe(exactRenewedExpiry);
    expect(kernel.commands[0]).toEqual(
      expect.objectContaining({ expectedLeaseExpiresAtMs: exactRenewedExpiry })
    );
  });

  it("heartbeats a live effect and completes against the most recently renewed exact expiry", async () => {
    let now = 2_000_000_000_000;
    const job = delivery("runtime.session.ensure");
    job.leaseExpiresAtMs = now + 1_000;
    let releaseHeartbeats: (() => void) | undefined;
    const heartbeatsObserved = new Promise<void>((resolve) => {
      releaseHeartbeats = resolve;
    });
    const returnedExpiries: number[] = [];
    const kernel = new FakeKernel([[job]], (options, renewalCount) => {
      now += 100;
      const leaseExpiresAtMs = Math.max(
        options.expectedLeaseExpiresAtMs,
        now + options.leaseDurationMs
      );
      returnedExpiries.push(leaseExpiresAtMs);
      if (renewalCount >= 3) releaseHeartbeats?.();
      return { leaseExpiresAtMs };
    });
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply() {
          await heartbeatsObserved;
        },
        async reconcile() {},
      },
      workerId: "runtime-worker-1",
      clock: () => now,
      leaseDurationMs: 1_000,
      leaseHeartbeatIntervalMs: 10,
      runtimeEffectTimeoutMs: 1_000,
    });

    await expect(worker.runOnce()).resolves.toMatchObject({ acknowledged: 1 });
    expect(kernel.renewals.length).toBeGreaterThanOrEqual(3);
    for (let index = 1; index < kernel.renewals.length; index += 1) {
      expect(kernel.renewals[index]?.expectedLeaseExpiresAtMs).toBe(returnedExpiries[index - 1]);
    }
    expect(kernel.commands[0]).toEqual(
      expect.objectContaining({
        expectedLeaseExpiresAtMs: returnedExpiries.at(-1),
      })
    );
  });

  it("aborts the adapter and emits no outcome when a heartbeat loses the exact lease", async () => {
    const now = 2_000_000_000_000;
    const job = delivery("runtime.session.ensure");
    job.leaseExpiresAtMs = now + 1_000;
    let adapterSignal: AbortSignal | undefined;
    let lateEffect = false;
    const kernel = new FakeKernel([[job]], (options, renewalCount) => {
      if (renewalCount > 1) return Promise.reject(undefined);
      return { leaseExpiresAtMs: options.expectedLeaseExpiresAtMs };
    });
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply(_input, signal) {
          adapterSignal = signal;
          await new Promise<void>((resolve) => {
            signal.addEventListener("abort", () => resolve(), { once: true });
          });
          if (!signal.aborted) lateEffect = true;
        },
        async reconcile() {},
      },
      workerId: "runtime-worker-1",
      clock: () => now,
      leaseDurationMs: 1_000,
      leaseHeartbeatIntervalMs: 10,
      runtimeEffectTimeoutMs: 1_000,
    });

    await expect(worker.runOnce()).rejects.toMatchObject({
      code: "runtime_timeout",
      retryable: true,
    });
    expect(adapterSignal?.aborted).toBe(true);
    expect(lateEffect).toBe(false);
    expect(kernel.interlocks).toHaveLength(1);
    expect(kernel.commands).toEqual([]);
    expect(worker.health()).toMatchObject({ failureSinceSuccess: true });
  });

  it("bounds a hung adapter, aborts it, and fails the latest exact lease as a timeout", async () => {
    const job = delivery("runtime.session.ensure");
    const kernel = new FakeKernel([[job]]);
    let adapterSignal: AbortSignal | undefined;
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply(_input, signal) {
          adapterSignal = signal;
          await new Promise<void>((resolve) => {
            signal.addEventListener("abort", () => resolve(), { once: true });
          });
        },
        async reconcile() {},
      },
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
      runtimeEffectTimeoutMs: 20,
      leaseHeartbeatIntervalMs: 500,
    });

    await expect(worker.runOnce()).resolves.toMatchObject({ retried: 1 });
    expect(adapterSignal?.aborted).toBe(true);
    expect(kernel.commands).toEqual([
      expect.objectContaining({
        type: "runtime.outbox.fail",
        errorCode: "runtime_timeout",
        expectedLeaseExpiresAtMs: job.leaseExpiresAtMs,
      }),
    ]);
  });

  it("preserves its health high-water across repeated clock rollback cycles", async () => {
    let now = 100;
    const worker = new RuntimeOutboxWorker({
      kernel: new FakeKernel([]),
      runtime: { apply: async () => {}, reconcile: async () => {} },
      workerId: "runtime-worker-1",
      clock: () => now,
    });

    await worker.runOnce();
    expect(worker.health()).toMatchObject({ lastSuccessAtMs: 100, failureSinceSuccess: false });
    now = 99;
    await worker.runOnce();
    await worker.runOnce();
    expect(worker.health()).toMatchObject({
      lastSuccessAtMs: 100,
      lastErrorAtMs: 100,
      failureSinceSuccess: true,
    });
    now = 101;
    await worker.runOnce();
    expect(worker.health()).toMatchObject({ lastSuccessAtMs: 101, failureSinceSuccess: false });
  });

  it("starts once and stops an abortable idle loop promptly", async () => {
    const kernel = new FakeKernel([]);
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: { apply: async () => {}, reconcile: async () => {} },
      workerId: "runtime-worker-1",
      idleDelayMs: 5,
      busyDelayMs: 1,
      errorDelayMs: 5,
    });

    worker.start();
    worker.start();
    await new Promise((resolve) => setTimeout(resolve, 12));
    await worker.stop();
    const countAfterStop = kernel.claimCount;
    await new Promise((resolve) => setTimeout(resolve, 8));

    expect(worker.running).toBe(false);
    expect(countAfterStop).toBeGreaterThan(0);
    expect(kernel.claimCount).toBe(countAfterStop);
  });

  it("cancels and joins a manual run even when no background loop was started", async () => {
    const kernel = new FakeKernel([[delivery("runtime.session.ensure")]]);
    let markApplyStarted: (() => void) | undefined;
    const applyStarted = new Promise<void>((resolve) => {
      markApplyStarted = resolve;
    });
    let adapterSignal: AbortSignal | undefined;
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply(_input, signal) {
          adapterSignal = signal;
          markApplyStarted?.();
          await new Promise<void>((resolve) => {
            signal.addEventListener("abort", () => resolve(), { once: true });
          });
        },
        async reconcile() {},
      },
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
    });

    const running = worker.runOnce();
    await applyStarted;
    const stopping = worker.stop();

    await expect(Promise.all([running, stopping])).resolves.toBeDefined();
    expect(adapterSignal?.aborted).toBe(true);
    expect(kernel.commands).toEqual([]);
  });

  it("routes a marked attempt only through reconciliation and never reacquires its interlock", async () => {
    const job = delivery(
      "runtime.session.ensure",
      1,
      2,
      SESSION_ID,
      "canonical-agent",
      "reconcile"
    );
    const kernel = new FakeKernel([[job]]);
    const calls: string[] = [];
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply() {
          calls.push("apply");
        },
        async reconcile() {
          calls.push("reconcile");
        },
      },
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
    });

    await expect(worker.runOnce()).resolves.toMatchObject({ acknowledged: 1 });
    expect(calls).toEqual(["reconcile"]);
    expect(kernel.interlocks).toEqual([]);
    expect(kernel.commands).toEqual([
      expect.objectContaining({
        type: "runtime.outbox.acknowledge",
        outboxId: job.outboxId,
        expectedAttempt: 2,
      }),
    ]);
  });

  it("does not invoke the adapter when the durable interlock cannot be acquired", async () => {
    const job = delivery("runtime.session.ensure");
    const calls: string[] = [];
    const kernel: RuntimeOutboxKernel = {
      async claimRuntimeOutbox() {
        return [job];
      },
      async renewRuntimeOutboxLease(options) {
        return { leaseExpiresAtMs: options.expectedLeaseExpiresAtMs };
      },
      async markRuntimeOutboxDispatch() {
        throw new Error("lease changed");
      },
      async dispatch(command) {
        calls.push(command.type);
        throw new Error("unexpected outcome");
      },
    };
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply() {
          calls.push("apply");
        },
        async reconcile() {
          calls.push("reconcile");
        },
      },
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
    });

    await expect(worker.runOnce()).rejects.toThrow("lease changed");
    expect(calls).toEqual([]);
  });
});
