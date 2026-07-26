import { NextRequest, NextResponse } from "next/server";
// Issue #11 (§2.1 + §2.2): GET/PUT settings for both User and Repo scopes.
// One route serves all settings sections; Models is the only one wired here.
// Mirrors the route conventions in src/app/api/telegram/settings/route.ts
// (NextRequest/NextResponse, x-username / x-user-role headers, audit()).
import { getMeta } from "@/lib/ai-sessions";
import { getGitDirectoryInfo } from "@/lib/git-worktree";
import { audit } from "@/lib/audit-log";
import {
  mergeModels,
  readRepoSettings,
  readUserSettings,
  repoSettingsPath,
  writeRepoSettings,
  writeUserSettings,
} from "@/lib/settings/store";
import { resolveModelSettings } from "@/lib/settings/resolve";
import { requireVerifiedAdmin } from "@/lib/request-actor";
import { validateModelsPatch } from "@/lib/settings/validate";
import type { ScopedSettings, SettingsScope } from "@/lib/settings/types";

// Defense-in-depth: the middleware-projected x-user-role header must say admin
// AND the identity must re-verify from the session JWT. A spoofed header alone
// (e.g. if the proxy middleware were ever bypassed) can no longer grant admin.
async function isAdmin(req: NextRequest): Promise<boolean> {
  return req.headers.get("x-user-role") === "admin" && (await requireVerifiedAdmin(req.headers));
}

/**
 * Resolve the repo root for a session: the worktree's repoRoot if recorded,
 * else the git root of the session cwd. Returns null when no repo context.
 */
function repoRootForSession(session: string | null): string | null {
  if (!session) return null;
  const meta = getMeta(session);
  if (!meta) return null;
  if (meta.worktree?.repoRoot) return meta.worktree.repoRoot;
  const dir = meta.cwd;
  if (!dir) return null;
  const info = getGitDirectoryInfo(dir);
  return info.isRepo && info.root ? info.root : null;
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const scope = searchParams.get("scope") as SettingsScope | null;
  if (scope !== "user" && scope !== "repo") {
    return NextResponse.json({ error: "invalid scope" }, { status: 400 });
  }

  const user = readUserSettings();

  if (scope === "user") {
    return NextResponse.json({
      scope,
      settings: user,
      resolved: resolveModelSettings(user.models, undefined),
      exists: true,
    });
  }

  // repo scope
  const session = searchParams.get("session");
  const repoRoot = repoRootForSession(session);
  if (!repoRoot) {
    return NextResponse.json({ error: "no repo context for session" }, { status: 404 });
  }

  const repo = readRepoSettings(repoRoot);
  return NextResponse.json({
    scope,
    settings: repo.settings,
    resolved: resolveModelSettings(user.models, repo.settings.models),
    repoPath: repoSettingsPathSafe(repoRoot),
    exists: repo.exists,
    ...(repo.parseError ? { parseError: true } : {}),
  });
}

// Wrap path resolution so a guard failure (sensitive/traversal) doesn't leak a
// stack — returns the relative path label instead.
function repoSettingsPathSafe(repoRoot: string): string {
  try {
    return repoSettingsPath(repoRoot);
  } catch {
    return ".terminalx/settings.toml";
  }
}

export async function PUT(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }

  const scope = body.scope as SettingsScope | undefined;
  if (scope !== "user" && scope !== "repo") {
    return NextResponse.json({ error: "invalid scope" }, { status: 400 });
  }

  const validated = validateModelsPatch(body.models);
  if (!validated.ok) {
    return NextResponse.json({ error: validated.error }, { status: 400 });
  }

  const user = readUserSettings();

  if (scope === "user") {
    const next: ScopedSettings = {
      ...user,
      version: 1,
      models: mergeModels(user.models, validated.patch),
    };
    await writeUserSettings(next);
    return NextResponse.json({
      settings: next,
      resolved: resolveModelSettings(next.models, undefined),
    });
  }

  // repo scope: admin-gated, repoRoot required.
  if (!(await isAdmin(req))) {
    return NextResponse.json({ error: "admin required" }, { status: 403 });
  }
  const session = typeof body.session === "string" ? body.session : null;
  const repoRoot = repoRootForSession(session);
  if (!repoRoot) {
    return NextResponse.json({ error: "no repo context" }, { status: 409 });
  }

  let prior: ScopedSettings;
  try {
    prior = readRepoSettings(repoRoot).settings;
  } catch {
    return NextResponse.json({ error: "invalid repo path" }, { status: 400 });
  }

  const next: ScopedSettings = {
    ...prior,
    version: 1,
    models: mergeModels(prior.models, validated.patch),
  };

  try {
    await writeRepoSettings(repoRoot, next);
  } catch (err) {
    console.error("[api/settings PUT repo]", err);
    return NextResponse.json({ error: "write failed" }, { status: 500 });
  }

  audit("settings_repo_updated", {
    username: req.headers.get("x-username") ?? undefined,
    detail: "models",
  });

  return NextResponse.json({
    settings: next,
    resolved: resolveModelSettings(user.models, next.models),
  });
}
