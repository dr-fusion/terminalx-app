import { NextRequest, NextResponse } from "next/server";
import * as fs from "fs";
import { listSessions, createSession, killSession } from "@/lib/tmux";
import { getUserScoping, canAccessSession, scopedSessionName } from "@/lib/session-scope";
import { audit } from "@/lib/audit-log";
import {
  listMetadata,
  saveMeta,
  deleteMeta,
  getMeta,
  commandForKind,
  isValidKind,
  ensureManagedSession,
} from "@/lib/ai-sessions";
// Issue #4: validation message is now sourced from the harness registry so new
// harnesses (cursor/opencode) need no edit here.
import { listHarnesses, getHarness } from "@/lib/harnesses/registry";
// Issue #11: resolve the effective Models settings for a new session and thread
// the chosen model + plan mode into the harness command (data-driven via the
// registry's modelFlag/planModeFlag — no per-CLI hard-coding here).
import { resolveSessionModelSettings } from "@/lib/settings/session-settings";
import { modelOptionsForKind } from "@/lib/harnesses/session-model";
import { listTopics } from "@/lib/telegram/state";
import { botIsConfigured, type BotIdentity } from "@/lib/telegram/auth";
import { ensureTopicForSession } from "@/lib/telegram/bot";
import { getEnsureTopic } from "@/lib/telegram/bot-bridge";
import { getConfiguredMaxSessions } from "@/lib/security-config";
import { assertNotSensitivePath, resolveSafePath } from "@/lib/file-service";
import { createGitWorktreeForSession, removeGitWorktree } from "@/lib/git-worktree";
// Workspace config (feature #5): resolve repo config, allocate a per-workspace
// port, copy declared files into a fresh worktree, prefix env, run setup.
import { resolveWorkspaceConfig, copyConfiguredFiles } from "@/lib/workspace-config";
import { allocateWorkspacePort } from "@/lib/workspace-port";
import { withWorkspaceEnv, runSetup } from "@/lib/workspace-setup";

/**
 * Accept either an array of paths or a comma/newline-separated string from the
 * dialog and normalize to a trimmed, de-duplicated, relative-only list. Returns
 * undefined when nothing usable is supplied so the lib applies its env default.
 */
function normalizeSymlinkPaths(input: unknown): string[] | undefined {
  if (input === undefined || input === null) return undefined;
  const raw = Array.isArray(input) ? input : typeof input === "string" ? input.split(/[,\n]/) : [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of raw) {
    const trimmed = typeof entry === "string" ? entry.trim() : "";
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  // An explicit empty selection should disable sharing (override env default),
  // so return [] rather than undefined when the caller sent something.
  return out;
}

function resolveSessionStartDir(requestedCwd: unknown): string {
  const requested =
    typeof requestedCwd === "string" && requestedCwd.trim() ? requestedCwd.trim() : ".";
  const startDir = resolveSafePath(requested);
  assertNotSensitivePath(startDir);
  const stats = fs.statSync(startDir);
  if (!stats.isDirectory()) {
    throw new Error("Path is not a directory");
  }
  return startDir;
}

function directoryErrorResponse(message: string): { error: string; status: number } {
  if (message.includes("outside the allowed root") || message.includes("sensitive path")) {
    return { error: "Access denied", status: 403 };
  }
  if (message.includes("ENOENT") || message.includes("no such file")) {
    return { error: "Directory not found", status: 404 };
  }
  if (message.includes("not a directory")) {
    return { error: "Path is not a directory", status: 400 };
  }
  return { error: "Invalid start directory", status: 400 };
}

export async function GET(req: NextRequest) {
  try {
    const { username, shouldScope } = getUserScoping(req.headers);
    let sessions = listSessions();

    if (shouldScope && !username) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }
    if (shouldScope && username) {
      sessions = sessions.filter((s) => canAccessSession(username, "user", s.name));
    }

    const metadata = listMetadata();
    const byName = new Map(metadata.map((m) => [m.name, m]));
    const telegramByName = new Map(listTopics().map((t) => [t.sessionName, t]));
    const annotated = sessions.map((s) => {
      const meta = byName.get(s.name);
      const telegram = telegramByName.get(s.name);
      return {
        ...s,
        kind: meta?.kind ?? "bash",
        cwd: meta?.cwd ?? s.activePath,
        worktree: meta?.worktree,
        // Feature #5: surface the per-workspace injected port + setup lifecycle so
        // clients (command palette, workspace UI) can read TERMINALX_PORT and the
        // setup status. Persisted on create but previously dropped from this list.
        port: meta?.port,
        setup: meta?.setup,
        managed: ensureManagedSession(s.name),
        telegram: telegram
          ? {
              topicId: telegram.topicId,
              viewMode: telegram.viewMode ?? "chat",
              endedAtMs: telegram.endedAtMs,
            }
          : null,
      };
    });

    return NextResponse.json({ sessions: annotated });
  } catch (err) {
    console.error("[api/sessions GET]", err);
    return NextResponse.json({ error: "Failed to list sessions" }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  if (process.env.TERMINUS_READ_ONLY === "true") {
    return NextResponse.json(
      { error: "Session creation disabled in read-only mode" },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    if (body?.dangerouslySkipPermissions === true) {
      return NextResponse.json(
        {
          error:
            "LocalTmux sessions cannot skip harness permissions; dangerouslySkipPermissions is not allowed",
        },
        { status: 400 }
      );
    }
    // `skipSetup` (feature #5): let the dashboard create without auto-running setup.
    const { name, kind, cwd, worktree, skipSetup } = body;

    if (!name || typeof name !== "string") {
      return NextResponse.json({ error: "Missing or invalid session name" }, { status: 400 });
    }

    if (!/^[a-zA-Z0-9_.\-]+$/.test(name)) {
      return NextResponse.json(
        { error: "Invalid session name: only alphanumeric, underscore, hyphen, and dot allowed" },
        { status: 400 }
      );
    }

    const sessionKind = kind === undefined ? "bash" : kind;
    if (!isValidKind(sessionKind)) {
      // Issue #4: dynamic list from the registry instead of a hard-coded string.
      const ids = listHarnesses()
        .map((h) => h.id)
        .join(", ");
      return NextResponse.json(
        { error: `Invalid session kind: expected one of ${ids}` },
        { status: 400 }
      );
    }

    const { username, role, hasIdentity } = getUserScoping(req.headers);
    if (!hasIdentity) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }
    const finalName = scopedSessionName(name, username);
    const maxSessions = getConfiguredMaxSessions();
    if (listSessions().filter((s) => ensureManagedSession(s.name)).length >= maxSessions) {
      return NextResponse.json(
        { error: `Maximum number of sessions reached (${maxSessions})` },
        { status: 429 }
      );
    }

    let startDir: string;
    let createdWorktree:
      | {
          repoRoot: string;
          worktreePath: string;
          startDir: string;
          branch: string;
          linkedPaths: string[];
        }
      | undefined;
    // Source checkout to copy declared files FROM (the dir the user selected,
    // before it was rebased onto the worktree path).
    let sourceCheckout: string | undefined;
    try {
      startDir = resolveSessionStartDir(cwd);
      if (worktree?.create === true) {
        sourceCheckout = startDir;
        const symlinkPaths = normalizeSymlinkPaths(worktree.symlinkPaths);
        createdWorktree = createGitWorktreeForSession(
          startDir,
          worktree.branch,
          symlinkPaths ? { symlinkPaths } : undefined
        );
        startDir = createdWorktree.startDir;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const { error, status } = directoryErrorResponse(message);
      return NextResponse.json({ error: worktree?.create === true ? message : error }, { status });
    }

    // --- Workspace config (feature #5) -------------------------------------
    // Resolve config for the repo backing this session, allocate a stable
    // per-workspace port, copy declared files into a fresh worktree, and prefix
    // the session command with the workspace env so the interactive shell
    // inherits TERMINALX_PORT + config.env. Never throws on missing/malformed
    // config — degrades to defaults.
    const wsRepoRoot = createdWorktree?.repoRoot ?? startDir;
    let port: number;
    try {
      port = await allocateWorkspacePort();
    } catch {
      // Port range exhausted — fail clearly so the user can widen the range.
      if (createdWorktree) {
        removeGitWorktree(createdWorktree.worktreePath, createdWorktree.repoRoot);
      }
      return NextResponse.json(
        { error: "No free workspace port available — widen TERMINALX_PORT_RANGE" },
        { status: 503 }
      );
    }
    const wsConfig = resolveWorkspaceConfig(wsRepoRoot, { port });
    if (createdWorktree && sourceCheckout) {
      // Copy `.env`/`.env.local` "if you have one" into the new worktree.
      copyConfiguredFiles(sourceCheckout, createdWorktree.worktreePath, wsConfig.copyFiles);
    }

    // --- Models settings (feature #11) -------------------------------------
    // Resolve the effective Models settings for this repo (registry default <
    // user < repo) and thread the chosen model + plan mode into the harness
    // command. modelOptionsForKind drops the model when its harness prefix does
    // not match the session kind, so a Codex default never reaches `claude`.
    // With no model set (or a non-matching harness), commandForKind omits the
    // model argument and keeps the standard LocalTmux lifecycle wrapper.
    const sessionModel = resolveSessionModelSettings(wsRepoRoot);
    const modelOpts = modelOptionsForKind(sessionKind, {
      // Only pass an explicit model: a bare registry default lets the CLI pick
      // its own default so vanilla sessions keep the legacy command unchanged.
      modelId: sessionModel.modelExplicit ? sessionModel.modelId : undefined,
      planMode: sessionModel.planMode,
    });
    const launchedModelId = modelOpts.model ? `${sessionKind}:${modelOpts.model}` : undefined;
    const baseCommand = commandForKind(sessionKind, modelOpts);
    // Persist the resolved Models settings only for harnesses that drive a model
    // (those with a binary). bash has no model so its records stay legacy-clean.
    const persistModelMeta = getHarness(sessionKind)?.command.bin != null;

    const wsEnv = { TERMINALX_PORT: String(port), ...wsConfig.env };
    const command = baseCommand
      ? withWorkspaceEnv(baseCommand, wsEnv)
      : withWorkspaceEnv("exec bash -l", wsEnv);

    try {
      createSession(finalName, command ?? undefined, startDir);
    } catch (err) {
      if (createdWorktree) {
        removeGitWorktree(createdWorktree.worktreePath, createdWorktree.repoRoot);
      }
      throw err;
    }

    // Setup auto-runs only on worktree creation with a configured setup script,
    // unless the caller opted out via skipSetup.
    const willRunSetup = Boolean(createdWorktree && wsConfig.setup && skipSetup !== true);
    await saveMeta({
      name: finalName,
      kind: sessionKind,
      createdAt: new Date().toISOString(),
      createdBy: username || undefined,
      managed: true,
      cwd: startDir,
      worktree: createdWorktree
        ? {
            repoRoot: createdWorktree.repoRoot,
            path: createdWorktree.worktreePath,
            branch: createdWorktree.branch,
            linkedPaths: createdWorktree.linkedPaths,
          }
        : undefined,
      port,
      setup: wsConfig.setup ? { status: willRunSetup ? "pending" : "skipped" } : undefined,
      // Feature #11: persist only the validated model actually passed to the
      // harness. Invalid, implicit, or provider-mismatched settings must not be
      // recorded as though they launched. Bash remains legacy-clean.
      ...(persistModelMeta
        ? {
            modelId: launchedModelId,
            effort: sessionModel.effort,
            personality: sessionModel.personality,
            planMode: sessionModel.planMode,
            fastMode: sessionModel.fastMode,
          }
        : {}),
    });

    // Fire-and-stream the setup run (async). Status is polled via GET /api/sessions.
    if (willRunSetup && createdWorktree && wsConfig.setup) {
      void runSetup({
        sessionName: finalName,
        cwd: createdWorktree.worktreePath,
        command: wsConfig.setup.command,
        env: wsEnv,
        timeoutSeconds: wsConfig.setup.timeoutSeconds ?? 1800,
      });
    }
    let telegramTopic: {
      topicId: number;
      sessionName: string;
      viewMode: string;
      url: string;
      created: boolean;
    } | null = null;
    if (botIsConfigured()) {
      const identity: BotIdentity = {
        username: username ?? "web",
        role: role === "user" ? "user" : "admin",
      };
      try {
        // Attach in the bot-owning graph so its streamer has a single owner.
        const ensure = getEnsureTopic() ?? ensureTopicForSession;
        const result = await ensure(identity, finalName, "chat");
        telegramTopic = result.topic;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.warn(`[telegram] failed to bind web-created session ${finalName}: ${message}`);
      }
    }
    audit("session_created", {
      username: username || undefined,
      detail: `${finalName} (${sessionKind})`,
    });
    return NextResponse.json(
      {
        success: true,
        name: finalName,
        kind: sessionKind,
        cwd: startDir,
        worktree: createdWorktree
          ? {
              repoRoot: createdWorktree.repoRoot,
              path: createdWorktree.worktreePath,
              branch: createdWorktree.branch,
            }
          : undefined,
        telegram: telegramTopic,
      },
      { status: 201 }
    );
  } catch (err) {
    console.error("[api/sessions POST]", err);
    return NextResponse.json({ error: "Failed to create session" }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  if (process.env.TERMINUS_READ_ONLY === "true") {
    return NextResponse.json(
      { error: "Session deletion disabled in read-only mode" },
      { status: 403 }
    );
  }

  try {
    const body = await req.json();
    const { name } = body;

    if (!name || typeof name !== "string") {
      return NextResponse.json({ error: "Missing or invalid session name" }, { status: 400 });
    }

    const { username, role, shouldScope } = getUserScoping(req.headers);

    if (shouldScope && (!username || !canAccessSession(username, role, name))) {
      return NextResponse.json({ error: "Cannot delete another user's session" }, { status: 403 });
    }

    if (!ensureManagedSession(name)) {
      return NextResponse.json(
        { error: "Refusing to delete a tmux session not managed by TerminalX" },
        { status: 403 }
      );
    }

    const meta = getMeta(name);
    killSession(name);
    if (meta?.worktree) {
      // Removes the worktree and any shared symlinks WITHOUT touching the
      // shared source (rmSync/unlink never follow the link into its target).
      removeGitWorktree(meta.worktree.path, meta.worktree.repoRoot, meta.worktree.linkedPaths);
    }
    await deleteMeta(name);
    audit("session_deleted", { username: username || undefined, detail: name });
    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("[api/sessions DELETE]", err);
    return NextResponse.json({ error: "Failed to delete session" }, { status: 500 });
  }
}
