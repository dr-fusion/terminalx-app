/**
 * Setup + run-script execution for workspace config. Setup runs once on
 * worktree creation (transient tmux session, streamed to a panel); run scripts
 * execute on demand in their own transient session. Both reuse the existing
 * tmux + pty-manager pipe — no new transport.
 *
 * The command builders here mirror the single-quote escaping pattern used by
 * `commandForKind` in ai-sessions.ts so env values / commands are never
 * concatenated raw into the shell (command-injection mitigation, spec §9).
 */
import { createSession, killSession, hasSession } from "./tmux";
import { getMeta, saveMeta, type SessionMeta } from "./ai-sessions";
import { interpolate } from "./workspace-config";

/** Escape a value so it is safe inside single quotes: `'` -> `'\''`. */
function escapeSingle(value: string): string {
  return value.replace(/'/g, `'\\''`);
}

/** Build `export K='v'; export K2='v2'` for the given env (single-quoted). */
export function buildWorkspaceEnvExports(env: Record<string, string>): string {
  return Object.entries(env)
    .map(([k, v]) => `export ${k}='${escapeSingle(v)}'`)
    .join("; ");
}

/**
 * Wrap an inner command so it inherits the workspace env. The exports live
 * INSIDE the tmux session's own login shell (not the node-pty allowlist), so
 * the pty-manager env allowlist is untouched.
 */
export function withWorkspaceEnv(inner: string, env: Record<string, string>): string {
  const exports = buildWorkspaceEnvExports(env);
  if (!exports) return inner;
  return `bash -lc '${exports}; ${escapeSingle(inner)}'`;
}

/**
 * Build the transient setup command: export env, run setup, print the exit
 * marker, then EXIT (no interactive tail — setup is transient).
 */
export function buildSetupCommand(command: string, env: Record<string, string>): string {
  const exports = buildWorkspaceEnvExports(env);
  const prefix = exports ? `${exports}; ` : "";
  const inner = `${prefix}${command}; ec=$?; echo; echo "[setup exited with code $ec]"; exit $ec`;
  return `bash -lc '${escapeSingle(inner)}'`;
}

/**
 * Build a run-script command. Unlike setup, it keeps the shell alive on exit so
 * a crashed dev server can be inspected (mirrors commandForKind's bash tail).
 */
export function buildRunCommand(
  scriptName: string,
  command: string,
  env: Record<string, string>
): string {
  const exports = buildWorkspaceEnvExports(env);
  const prefix = exports ? `${exports}; ` : "";
  const inner =
    `${prefix}${command}; ec=$?; echo; ` +
    `echo "[run ${scriptName} exited with code $ec — dropping to bash]"; exec bash -l`;
  return `bash -lc '${escapeSingle(inner)}'`;
}

/** Interpolate `${VAR}` tokens in a command at execute time (port now known). */
export function resolveScriptCommand(command: string, env: Record<string, string>): string {
  return interpolate(command, env);
}

function now(): string {
  return new Date().toISOString();
}

async function patchSetupStatus(
  sessionName: string,
  patch: Partial<NonNullable<SessionMeta["setup"]>>
): Promise<void> {
  const meta = getMeta(sessionName);
  if (!meta) return;
  await saveMeta({
    ...meta,
    setup: { ...(meta.setup ?? { status: "pending" }), ...patch },
  });
}

/** Poll until the transient session exits or the timeout elapses. */
async function waitForSessionExit(
  name: string,
  timeoutSeconds: number
): Promise<{ timedOut: boolean }> {
  const deadline = Date.now() + timeoutSeconds * 1000;
  // Give tmux a beat to spawn before the first existence probe.
  await delay(250);
  while (Date.now() < deadline) {
    if (!hasSession(name)) return { timedOut: false };
    await delay(500);
  }
  return { timedOut: true };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Run the setup command in a transient tmux session "<sessionName>--setup",
 * streaming to the terminal bus. Resolves when the command exits (or times
 * out). Updates SessionMeta.setup throughout. Never throws — a setup failure
 * must not break the primary session.
 */
export async function runSetup(opts: {
  sessionName: string;
  cwd: string;
  command: string;
  env: Record<string, string>; // includes TERMINALX_PORT + config.env
  timeoutSeconds: number;
}): Promise<{ exitCode: number; timedOut: boolean; setupName: string }> {
  const setupName = `${opts.sessionName}--setup`;
  // A re-run kills any prior transient setup session of the same name.
  try {
    if (hasSession(setupName)) killSession(setupName);
  } catch {
    /* ignore */
  }

  await patchSetupStatus(opts.sessionName, { status: "running", startedAt: now() });

  const resolvedCommand = resolveScriptCommand(opts.command, opts.env);
  const wrapped = buildSetupCommand(resolvedCommand, opts.env);

  let timedOut = false;
  try {
    createSession(setupName, wrapped, opts.cwd);
    ({ timedOut } = await waitForSessionExit(setupName, opts.timeoutSeconds));
  } catch {
    await patchSetupStatus(opts.sessionName, {
      status: "failed",
      finishedAt: now(),
      exitCode: -1,
    });
    return { exitCode: -1, timedOut: false, setupName };
  }

  // The transient session's `exit $ec` ends the tmux session when setup
  // finishes; we can't read its exit code after the fact, so success is
  // "exited cleanly within the timeout". A timeout is a failure.
  const exitCode = timedOut ? 124 : 0;
  if (timedOut) {
    try {
      killSession(setupName);
    } catch {
      /* already gone */
    }
  }
  await patchSetupStatus(opts.sessionName, {
    status: timedOut ? "failed" : "succeeded",
    finishedAt: now(),
    exitCode,
  });
  return { exitCode, timedOut, setupName };
}

/**
 * Execute a named run script in its own transient tmux session, returning the
 * session name the client can attach to. The command is interpolated and the
 * env exported inside the session's shell.
 */
export function executeRunScript(opts: {
  sessionName: string;
  scriptName: string;
  cwd: string;
  command: string;
  env: Record<string, string>;
}): { runSessionName: string } {
  const ts = Date.now();
  const runSessionName = `${opts.sessionName}--run-${opts.scriptName}-${ts}`;
  const resolvedCommand = resolveScriptCommand(opts.command, opts.env);
  const wrapped = buildRunCommand(opts.scriptName, resolvedCommand, opts.env);
  createSession(runSessionName, wrapped, opts.cwd);
  return { runSessionName };
}
