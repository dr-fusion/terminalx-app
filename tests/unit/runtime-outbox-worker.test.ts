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

function marker(sessionId = SESSION_ID): string {
  return `v1:${sessionId}\n`;
}

function delivery(
  kind: RuntimeOutboxDelivery["kind"],
  generation = 1,
  attempts = 1,
  sessionId = SESSION_ID,
  tmuxName = "canonical-agent"
): RuntimeOutboxDelivery {
  const base = {
    outboxId: `outbox-${kind}-${generation}`,
    sessionId,
    sessionSequence: generation,
    attempts,
    leaseOwner: "runtime-worker-1",
    leaseExpiresAtMs: 2_000_000_030_000,
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
    const result = this.results.shift();
    if (!result) throw new Error("Unexpected executor call");
    return result;
  }
}

function operation(args: readonly string[]): string {
  return args[4] ?? "unknown";
}

function runtimeWith(
  executor: ExactCommandExecutor,
  options: {
    log?: string[];
    states?: RuntimeWriteStateUpdate[];
    currentBinding?: boolean;
  } = {}
) {
  const states = options.states ?? [];
  const terminations: string[] = [];
  const runtime = new LocalTmuxRuntime({
    executor,
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
        terminations.push(`${input.reason}:${input.tmuxName}`);
        options.log?.push(`terminate:${input.reason}`);
      },
      async isCurrentRuntimeBinding() {
        return options.currentBinding ?? true;
      },
    },
  });
  return { runtime, states, terminations };
}

describe("LocalTmuxRuntime", () => {
  it("creates and marks an exact canonical session on a dedicated scrubbed tmux server", async () => {
    const executor = new ScriptedExecutor([
      failure("no server running on /tmp/tmux"),
      success(),
      success(marker()),
      success(`canonical-agent\t1\t${SESSION_ID}\t1\n`),
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
    expect(executor.requests).toHaveLength(4);
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
      `v1:${SESSION_ID}`,
      ";",
    ]);
    expect(create.args).toContain("new-session");
    expect(create.args).toContain("-E");
    expect(create.args).toContain("@terminalx_runtime_server");
    expect(create.args).toContain("@terminalx_session_id");
    expect(create.args).toContain("@terminalx_runtime_authorization_generation");
    expect(create.args).toContain("=canonical-agent:");
    expect(create.args).toEqual(expect.arrayContaining(["prefix", "None", "prefix2", "None"]));
  });

  it("is idempotent for its exact binding and refuses an unmanaged name collision", async () => {
    const exactExecutor = new ScriptedExecutor([
      success(marker()),
      success(`canonical-agent\t1\t${SESSION_ID}\t1\n`),
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

  it("fences writes before updating tmux and terminating canonical PTYs", async () => {
    const log: string[] = [];
    const executor = new ScriptedExecutor(
      [success(marker()), success(`canonical-agent\t1\t${SESSION_ID}\t1\n`), success(), success()],
      log
    );
    const { runtime, states, terminations } = runtimeWith(executor, { log });

    await runtime.apply(delivery("runtime.authorization.fence", 2));

    expect(log[0]).toBe("state:fenced:2");
    expect(log).toEqual([
      "state:fenced:2",
      "exec:show-options",
      "exec:list-sessions",
      "exec:set-option",
      "exec:detach-client",
      "terminate:authorization-fence",
    ]);
    expect(states.at(-1)?.state).toBe("fenced");
    expect(terminations).toEqual(["authorization-fence:canonical-agent"]);
  });

  it("does not let stale work downgrade an in-memory fence", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(`canonical-agent\t1\t${SESSION_ID}\t1\n`),
      success(),
      success(),
      success(marker()),
      success(`canonical-agent\t1\t${SESSION_ID}\t2\n`),
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

  it("fails a stale retire closed before any tmux or PTY effect", async () => {
    const executor = new ScriptedExecutor([]);
    const { runtime, states, terminations } = runtimeWith(executor, {
      currentBinding: false,
    });

    await expect(runtime.apply(delivery("runtime.session.retire", 1))).rejects.toMatchObject({
      code: "runtime_invalid_state",
      retryable: false,
    });
    expect(executor.requests).toEqual([]);
    expect(states).toEqual([]);
    expect(terminations).toEqual([]);
  });

  it("retires only an exact current canonical generation", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(`canonical-agent\t1\t${SESSION_ID}\t2\n`),
      success(),
      success(),
    ]);
    const { runtime, states, terminations } = runtimeWith(executor);

    await runtime.apply(delivery("runtime.session.retire", 2));

    expect(states.at(-1)?.state).toBe("retired");
    expect(terminations).toEqual(["retire:canonical-agent"]);
    expect(executor.requests.at(-1)?.args).toEqual([
      "-L",
      getCanonicalTmuxSocketName(SESSION_ID, {}),
      "-f",
      "/dev/null",
      "kill-session",
      "-t",
      "=canonical-agent:",
    ]);
  });

  it("rejects unbounded command timeouts", () => {
    expect(
      () =>
        new LocalTmuxRuntime({
          commandTimeoutMs: 0,
          fenceCallbacks: {
            updateWriteState() {},
            async terminateCanonicalPtys() {},
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
      success(`canonical-agent\t1\t${SESSION_ID}\t1\n`),
      failure("no server running on /tmp/tmux"),
      success(),
      success(marker(SECOND_SESSION_ID)),
      success(`canonical-agent-b\t1\t${SECOND_SESSION_ID}\t1\n`),
    ]);
    const { runtime } = runtimeWith(executor);

    await runtime.apply(delivery("runtime.session.ensure"));
    await runtime.apply(
      delivery("runtime.session.ensure", 1, 1, SECOND_SESSION_ID, "canonical-agent-b")
    );

    const firstSocket = getCanonicalTmuxSocketName(SESSION_ID, {});
    const secondSocket = getCanonicalTmuxSocketName(SECOND_SESSION_ID, {});
    expect(new Set(executor.requests.slice(0, 4).map((request) => request.args[1]))).toEqual(
      new Set([firstSocket])
    );
    expect(new Set(executor.requests.slice(4).map((request) => request.args[1]))).toEqual(
      new Set([secondSocket])
    );
    expect(firstSocket).not.toBe(secondSocket);
    expect(
      executor.requests.slice(0, 4).every((request) => !request.args.includes("canonical-agent-b"))
    ).toBe(true);
  });

  it("fails closed when a per-session socket contains any foreign session", async () => {
    const executor = new ScriptedExecutor([
      success(marker()),
      success(`canonical-agent\t1\t${SESSION_ID}\t1\nforeign\t1\t${SECOND_SESSION_ID}\t1\n`),
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

    await runtime.apply(delivery("runtime.session.retire", 2));

    expect(states).toEqual([
      {
        sessionId: SESSION_ID,
        runtimeAuthorizationGeneration: 2,
        state: "retired",
      },
    ]);
    expect(terminations).toEqual([]);
  });
});

class FakeKernel implements RuntimeOutboxKernel {
  readonly commands: SessionCommand[] = [];
  readonly claimOptions: RuntimeOutboxClaimOptions[] = [];
  claimCount = 0;

  constructor(private readonly batches: RuntimeOutboxDelivery[][]) {}

  async claimRuntimeOutbox(options: RuntimeOutboxClaimOptions): Promise<RuntimeOutboxDelivery[]> {
    this.claimCount += 1;
    this.claimOptions.push(options);
    return this.batches.shift() ?? [];
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
  it("claims leased work and acknowledges the exact attempt", async () => {
    const job = delivery("runtime.session.ensure", 1, 3);
    const kernel = new FakeKernel([[job]]);
    const runtime: RuntimeOutboxApplier = { apply: async () => {} };
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
        workerId: "runtime-worker-1",
      }),
    ]);
    expect(kernel.claimOptions).toEqual([
      {
        workerId: "runtime-worker-1",
        limit: 1,
        leaseDurationMs: 30_000,
      },
    ]);
  });

  it("does not misreport an acknowledgement transport failure as an effect failure", async () => {
    const job = delivery("runtime.session.ensure");
    const commands: SessionCommand[] = [];
    const kernel: RuntimeOutboxKernel = {
      async claimRuntimeOutbox() {
        return [job];
      },
      async dispatch(command) {
        commands.push(command);
        throw new Error("kernel unavailable");
      },
    };
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: { apply: async () => {} },
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
    });

    await expect(worker.runOnce()).rejects.toThrow("kernel unavailable");
    expect(commands).toHaveLength(1);
    expect(commands[0]).toMatchObject({ type: "runtime.outbox.acknowledge" });
  });

  it("retries transient failures but sends permanent conflicts to quarantine", async () => {
    const transient = delivery("runtime.session.ensure", 1, 1);
    const conflict = delivery("runtime.session.ensure", 1, 2);
    let calls = 0;
    const runtime: RuntimeOutboxApplier = {
      async apply() {
        calls += 1;
        throw calls === 1
          ? new RuntimeEffectError("runtime_timeout", true)
          : new RuntimeEffectError("runtime_conflict", false);
      },
    };
    const kernel = new FakeKernel([[transient, conflict]]);
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime,
      workerId: "runtime-worker-1",
      clock: () => 2_000_000_000_000,
    });

    await expect(worker.runOnce()).resolves.toMatchObject({ retried: 1, failedPermanently: 1 });
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
    const kernel = new FakeKernel([[delivery("runtime.session.ensure", 1, 2)]]);
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: {
        async apply() {
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

  it("starts once and stops an abortable idle loop promptly", async () => {
    const kernel = new FakeKernel([]);
    const worker = new RuntimeOutboxWorker({
      kernel,
      runtime: { apply: async () => {} },
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
});
