import * as pty from "node-pty";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { hasSession, isValidTmuxSessionName, tmuxTarget } from "./tmux";
import {
  CANONICAL_TMUX_CONFIG_FILE,
  buildCanonicalTmuxEnvironment,
  canonicalTmuxTarget,
} from "./runtime";

const CANONICAL_MANAGED_OPTION = "@terminalx_managed";
const CANONICAL_SESSION_ID_OPTION = "@terminalx_session_id";
const CANONICAL_SESSION_INCARNATION_OPTION = "@terminalx_session_incarnation";
const CANONICAL_AUTHORIZATION_GENERATION_OPTION = "@terminalx_runtime_authorization_generation";
const CANONICAL_SERVER_MARKER_OPTION = "@terminalx_runtime_server";
const CANONICAL_SESSION_BINDING_FORMAT = `#{session_id}\t#{${CANONICAL_MANAGED_OPTION}}\t#{${CANONICAL_SESSION_ID_OPTION}}\t#{${CANONICAL_AUTHORIZATION_GENERATION_OPTION}}\t#{${CANONICAL_SESSION_INCARNATION_OPTION}}\t#{${CANONICAL_SERVER_MARKER_OPTION}}`;
const IMMUTABLE_TMUX_SESSION_REF_PATTERN = /^\$[0-9]{1,20}$/;
const SESSION_INCARNATION_PATTERN = /^[0-9a-f]{64}$/;
const CANONICAL_TEAM_SESSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$/;

export interface CanonicalPtyBinding {
  teamSessionId: string;
  runtimeAuthorizationGeneration: number;
  tmuxSocketName: string;
  tmuxSessionRef: string;
  tmuxSessionIncarnation: string;
  readOnly: boolean;
}

export interface CanonicalTmuxSessionBindingRef {
  tmuxSessionRef: string;
  tmuxSessionIncarnation: string;
}

export interface PtyInstance {
  id: string;
  sessionName: string;
  process: pty.IPty;
  createdAt: Date;
  canonicalBinding?: CanonicalPtyBinding;
}

const activePtys = new Map<string, PtyInstance>();

let maxSessions = 20;

export function setMaxSessions(max: number): void {
  maxSessions = max;
}

export function getMaxSessions(): number {
  return maxSessions;
}

export function getActivePtyCount(): number {
  return activePtys.size;
}

export function createPty(
  sessionName: string,
  shell: string,
  cols: number,
  rows: number
): PtyInstance {
  if (activePtys.size >= maxSessions) {
    throw new Error(`Maximum number of PTY sessions reached (${maxSessions})`);
  }

  if (!isValidTmuxSessionName(sessionName)) {
    throw new Error("Invalid session name");
  }

  if (!hasSession(sessionName)) {
    throw new Error("Session does not exist. Create it from the dashboard first.");
  }

  return spawnPty(sessionName, shell, cols, rows, [
    "attach-session",
    "-t",
    tmuxTarget(sessionName),
  ]);
}

export function createCanonicalPty(
  sessionName: string,
  shell: string,
  cols: number,
  rows: number,
  binding: CanonicalPtyBinding
): PtyInstance {
  if (activePtys.size >= maxSessions) {
    throw new Error(`Maximum number of PTY sessions reached (${maxSessions})`);
  }
  if (!isValidTmuxSessionName(sessionName)) throw new Error("Invalid session name");
  if (
    !CANONICAL_TEAM_SESSION_ID_PATTERN.test(binding.teamSessionId) ||
    !Number.isSafeInteger(binding.runtimeAuthorizationGeneration) ||
    binding.runtimeAuthorizationGeneration < 1 ||
    !/^[a-zA-Z0-9_-]{1,64}$/.test(binding.tmuxSocketName) ||
    !IMMUTABLE_TMUX_SESSION_REF_PATTERN.test(binding.tmuxSessionRef) ||
    !SESSION_INCARNATION_PATTERN.test(binding.tmuxSessionIncarnation) ||
    typeof binding.readOnly !== "boolean"
  ) {
    throw new Error("Invalid canonical PTY binding");
  }
  const attachCommand = ["attach-session", "-E"];
  // tmux normally lets every attached client influence the shared window size.
  // An Observer is deliberately non-mutating, so exclude its PTY dimensions
  // from tmux sizing in addition to attaching it read-only.
  if (binding.readOnly) attachCommand.push("-r", "-f", "ignore-size");
  attachCommand.push("-t", binding.tmuxSessionRef);
  const args = [
    "-L",
    binding.tmuxSocketName,
    "-f",
    CANONICAL_TMUX_CONFIG_FILE,
    "if-shell",
    "-F",
    "-t",
    binding.tmuxSessionRef,
    canonicalPtyBindingPredicate(binding),
    attachCommand.join(" "),
    "display-message -p terminalx-runtime-binding-unavailable",
  ];
  // Admission binds the name and durable generation to both the tmux `$id`
  // and its per-session incarnation. The predicate and attach execute
  // over one tmux client connection, so a restarted server cannot reuse `$id`
  // between admission and attachment.
  return spawnPty(sessionName, shell, cols, rows, args, Object.freeze({ ...binding }));
}

export function resolveCanonicalTmuxSessionRef(input: {
  teamSessionId: string;
  tmuxName: string;
  runtimeAuthorizationGeneration: number;
  tmuxSocketName: string;
}): CanonicalTmuxSessionBindingRef {
  if (
    !CANONICAL_TEAM_SESSION_ID_PATTERN.test(input.teamSessionId) ||
    !isValidTmuxSessionName(input.tmuxName) ||
    !Number.isSafeInteger(input.runtimeAuthorizationGeneration) ||
    input.runtimeAuthorizationGeneration < 1 ||
    !/^[a-zA-Z0-9_-]{1,64}$/.test(input.tmuxSocketName)
  ) {
    throw new Error("Invalid canonical tmux binding lookup");
  }
  const output = execFileSync(
    "tmux",
    [
      "-L",
      input.tmuxSocketName,
      "-f",
      CANONICAL_TMUX_CONFIG_FILE,
      "display-message",
      "-p",
      "-t",
      canonicalTmuxTarget(input.tmuxName),
      CANONICAL_SESSION_BINDING_FORMAT,
    ],
    {
      encoding: "utf8",
      env: { ...buildCanonicalTmuxEnvironment(process.env) } as NodeJS.ProcessEnv,
      maxBuffer: 64 * 1024,
      timeout: 5_000,
    }
  ).trim();
  const [
    tmuxSessionRef = "",
    managed = "",
    sessionId = "",
    generation = "",
    tmuxSessionIncarnation = "",
    serverMarker = "",
    ...extra
  ] = output.split("\t");
  const markerIncarnation = parseServerIncarnation(serverMarker, input.teamSessionId);
  if (
    extra.length !== 0 ||
    !IMMUTABLE_TMUX_SESSION_REF_PATTERN.test(tmuxSessionRef) ||
    managed !== "1" ||
    sessionId !== input.teamSessionId ||
    generation !== String(input.runtimeAuthorizationGeneration) ||
    !SESSION_INCARNATION_PATTERN.test(tmuxSessionIncarnation) ||
    markerIncarnation !== tmuxSessionIncarnation
  ) {
    throw new Error("Canonical tmux binding is unavailable");
  }
  return Object.freeze({ tmuxSessionRef, tmuxSessionIncarnation });
}

function canonicalPtyBindingPredicate(binding: CanonicalPtyBinding): string {
  const serverMarker = `v2:${binding.teamSessionId}:${binding.tmuxSessionIncarnation}`;
  const conditions = [
    tmuxFormatEquals(`#{${CANONICAL_SERVER_MARKER_OPTION}}`, serverMarker),
    tmuxFormatEquals("#{session_id}", binding.tmuxSessionRef),
    tmuxFormatEquals(`#{${CANONICAL_MANAGED_OPTION}}`, "1"),
    tmuxFormatEquals(`#{${CANONICAL_SESSION_ID_OPTION}}`, binding.teamSessionId),
    tmuxFormatEquals(`#{${CANONICAL_SESSION_INCARNATION_OPTION}}`, binding.tmuxSessionIncarnation),
    tmuxFormatEquals(
      `#{${CANONICAL_AUTHORIZATION_GENERATION_OPTION}}`,
      String(binding.runtimeAuthorizationGeneration)
    ),
  ];
  return conditions.reduceRight((right, condition) =>
    right ? `#{&&:${condition},${right}}` : condition
  );
}

function tmuxFormatEquals(format: string, exactLiteral: string): string {
  return `#{==:${format},${exactLiteral}}`;
}

function parseServerIncarnation(marker: string, expectedTeamSessionId: string): string | null {
  const prefix = `v2:${expectedTeamSessionId}:`;
  if (!marker.startsWith(prefix)) return null;
  const sessionIncarnation = marker.slice(prefix.length);
  return SESSION_INCARNATION_PATTERN.test(sessionIncarnation) ? sessionIncarnation : null;
}

function spawnPty(
  sessionName: string,
  shell: string,
  cols: number,
  rows: number,
  args: string[],
  canonicalBinding?: CanonicalPtyBinding
): PtyInstance {
  const id = `pty-${sessionName}-${randomUUID()}`;

  // Build a sanitized environment for PTY processes.
  // NEVER spread process.env — it contains server secrets (JWT secret, admin password, etc.)
  const safeEnvKeys = [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_COLLATE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_MONETARY",
    "TZ",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "LESS",
    "LESSOPEN",
    "LESSCLOSE",
    "COLORTERM",
    "DISPLAY",
    "SSH_AUTH_SOCK",
    "XDG_RUNTIME_DIR",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "TERMINUS_ROOT",
  ];
  const safeEnv: Record<string, string> = {};
  for (const key of safeEnvKeys) {
    if (process.env[key]) {
      safeEnv[key] = process.env[key] as string;
    }
  }
  safeEnv.TERM = "xterm-256color";
  safeEnv.SHELL = shell;

  const proc = pty.spawn("tmux", args, {
    name: "xterm-256color",
    cols: Math.max(1, Math.min(cols, 500)),
    rows: Math.max(1, Math.min(rows, 200)),
    cwd: process.env.TERMINUS_ROOT || process.env.HOME || "/",
    env: safeEnv,
  });

  const instance: PtyInstance = {
    id,
    sessionName,
    process: proc,
    createdAt: new Date(),
    ...(canonicalBinding ? { canonicalBinding } : {}),
  };

  activePtys.set(id, instance);

  // Auto-cleanup when process exits
  proc.onExit(() => {
    activePtys.delete(id);
  });

  return instance;
}

export function destroyCanonicalPtys(input: {
  teamSessionId: string;
  runtimeAuthorizationGeneration: number;
  tmuxSessionRef: string;
  tmuxSessionIncarnation: string;
  includeCurrentGeneration?: boolean;
}): number {
  if (
    !IMMUTABLE_TMUX_SESSION_REF_PATTERN.test(input.tmuxSessionRef) ||
    !SESSION_INCARNATION_PATTERN.test(input.tmuxSessionIncarnation)
  ) {
    return 0;
  }
  let destroyed = 0;
  for (const instance of [...activePtys.values()]) {
    const binding = instance.canonicalBinding;
    if (
      !binding ||
      binding.teamSessionId !== input.teamSessionId ||
      binding.tmuxSessionRef !== input.tmuxSessionRef ||
      binding.tmuxSessionIncarnation !== input.tmuxSessionIncarnation
    ) {
      continue;
    }
    const stale = input.includeCurrentGeneration
      ? binding.runtimeAuthorizationGeneration <= input.runtimeAuthorizationGeneration
      : binding.runtimeAuthorizationGeneration < input.runtimeAuthorizationGeneration;
    if (!stale) continue;
    destroyPty(instance.id);
    destroyed += 1;
  }
  return destroyed;
}

export function resizePty(id: string, cols: number, rows: number): void {
  const instance = activePtys.get(id);
  if (!instance) {
    throw new Error(`PTY not found: ${id}`);
  }
  instance.process.resize(Math.max(1, Math.min(cols, 500)), Math.max(1, Math.min(rows, 200)));
}

export function destroyPty(id: string): void {
  const instance = activePtys.get(id);
  if (!instance) {
    return;
  }
  try {
    instance.process.kill();
  } catch {
    // Process may already be dead
  }
  activePtys.delete(id);
}

export function getPty(id: string): PtyInstance | undefined {
  return activePtys.get(id);
}

export function listPtys(): PtyInstance[] {
  return Array.from(activePtys.values());
}

export function destroyAllPtys(): void {
  for (const [id] of activePtys) {
    destroyPty(id);
  }
}
