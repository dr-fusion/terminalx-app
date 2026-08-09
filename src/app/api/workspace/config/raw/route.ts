import { NextRequest, NextResponse } from "next/server";
import * as fs from "fs";
import * as path from "path";
import { canAccessSession } from "@/lib/session-scope";
import { assertNotSensitivePath, resolveSafePath } from "@/lib/file-service";
import { audit } from "@/lib/audit-log";
import { parseToml, repoConfigPath, settingsTomlTemplate } from "@/lib/workspace-config";
import { resolveSessionWorkspace } from "@/lib/workspace-resolve";
import { resolveRequestActor } from "@/lib/request-actor";

/** Resolve the committed settings.toml path for a session or explicit repoRoot. */
function resolveTargetPath(session: string | null, repoRootParam: string | null): string | null {
  if (session) {
    const workspace = resolveSessionWorkspace(session);
    if (!workspace) return null;
    return repoConfigPath(workspace.repoRoot);
  }
  if (repoRootParam) {
    const safe = resolveSafePath(repoRootParam);
    assertNotSensitivePath(safe);
    return repoConfigPath(safe);
  }
  return null;
}

/**
 * GET /api/workspace/config/raw?session=<name> | ?repoRoot=<path>
 * Returns the raw committed settings.toml (or a seed template when missing).
 */
export async function GET(req: NextRequest) {
  const actor = await resolveRequestActor(req.headers);
  if (!actor) {
    return NextResponse.json({ error: "Access denied" }, { status: 403 });
  }
  const session = req.nextUrl.searchParams.get("session");
  const repoRootParam = req.nextUrl.searchParams.get("repoRoot");

  if (session && !canAccessSession(actor.username, actor.legacyRole, session)) {
    return NextResponse.json({ error: "Access denied" }, { status: 403 });
  }

  try {
    const target = resolveTargetPath(session, repoRootParam);
    if (!target) {
      return NextResponse.json({ error: "session or repoRoot is required" }, { status: 400 });
    }
    let content = "";
    let exists = false;
    try {
      content = fs.readFileSync(/* turbopackIgnore: true */ target, "utf-8");
      exists = true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      content = settingsTomlTemplate();
    }
    return NextResponse.json({ path: target, content, exists });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("outside the allowed root") || message.includes("sensitive path")) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }
    console.error("[api/workspace/config/raw GET]", err);
    return NextResponse.json({ error: "Failed to read settings.toml" }, { status: 500 });
  }
}

/**
 * PUT /api/workspace/config/raw  body { session?, repoRoot?, content }
 * Validates the TOML parses, writes the committed file, audits the edit.
 */
export async function PUT(req: NextRequest) {
  if (process.env.TERMINUS_READ_ONLY === "true") {
    return NextResponse.json(
      { error: "Config editing disabled in read-only mode" },
      { status: 403 }
    );
  }
  const actor = await resolveRequestActor(req.headers);
  if (!actor) {
    return NextResponse.json({ error: "Access denied" }, { status: 403 });
  }

  let body: { session?: string; repoRoot?: string; content?: unknown };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (typeof body.content !== "string") {
    return NextResponse.json({ error: "content must be a string" }, { status: 400 });
  }
  if (body.session && !canAccessSession(actor.username, actor.legacyRole, body.session)) {
    return NextResponse.json({ error: "Access denied" }, { status: 403 });
  }

  // Validate the TOML parses before writing — reject malformed input.
  try {
    parseToml(body.content);
  } catch (err) {
    return NextResponse.json(
      { error: "Invalid TOML", warnings: [(err as Error).message] },
      { status: 400 }
    );
  }

  try {
    const target = resolveTargetPath(body.session ?? null, body.repoRoot ?? null);
    if (!target) {
      return NextResponse.json({ error: "session or repoRoot is required" }, { status: 400 });
    }
    const targetDirectory = path.dirname(/* turbopackIgnore: true */ target);
    fs.mkdirSync(/* turbopackIgnore: true */ targetDirectory, { recursive: true });
    fs.writeFileSync(/* turbopackIgnore: true */ target, body.content, {
      encoding: "utf-8",
      mode: 0o644,
    });
    audit("workspace_config_edited", {
      username: actor.username,
      userId: actor.userId,
      detail: target,
    });
    return NextResponse.json({ success: true, path: target });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("outside the allowed root") || message.includes("sensitive path")) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }
    console.error("[api/workspace/config/raw PUT]", err);
    return NextResponse.json({ error: "Failed to write settings.toml" }, { status: 500 });
  }
}
