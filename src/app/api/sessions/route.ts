import { NextRequest, NextResponse } from "next/server";
import { listSessions, createSession, killSession } from "@/lib/tmux";
import { getUserScoping, canAccessSession, scopedSessionName } from "@/lib/session-scope";
import { audit } from "@/lib/audit-log";
import { listMetadata, saveMeta, deleteMeta, commandForKind, isValidKind } from "@/lib/ai-sessions";

export async function GET(req: NextRequest) {
  try {
    const { username, shouldScope } = getUserScoping(req.headers);
    let sessions = listSessions();

    if (shouldScope && username) {
      sessions = sessions.filter((s) => canAccessSession(username, "user", s.name));
    }

    const metadata = listMetadata();
    const byName = new Map(metadata.map((m) => [m.name, m]));
    const annotated = sessions.map((s) => ({
      ...s,
      kind: byName.get(s.name)?.kind ?? "bash",
    }));

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
    const { name, kind, dangerouslySkipPermissions } = body;

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
      return NextResponse.json(
        { error: "Invalid session kind: expected bash, claude, or codex" },
        { status: 400 }
      );
    }

    const { username } = getUserScoping(req.headers);
    const finalName = scopedSessionName(name, username);

    const command = commandForKind(sessionKind, {
      dangerouslySkipPermissions: Boolean(dangerouslySkipPermissions),
    });
    const startDir = process.env.TERMINUS_ROOT || process.env.HOME;
    createSession(finalName, command ?? undefined, startDir);
    if (sessionKind !== "bash") {
      await saveMeta({
        name: finalName,
        kind: sessionKind,
        createdAt: new Date().toISOString(),
        createdBy: username || undefined,
      });
    }
    audit("session_created", {
      username: username || undefined,
      detail: `${finalName} (${sessionKind})`,
    });
    return NextResponse.json(
      { success: true, name: finalName, kind: sessionKind },
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

    if (shouldScope && username && !canAccessSession(username, role, name)) {
      return NextResponse.json({ error: "Cannot delete another user's session" }, { status: 403 });
    }

    killSession(name);
    await deleteMeta(name);
    audit("session_deleted", { username: username || undefined, detail: name });
    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("[api/sessions DELETE]", err);
    return NextResponse.json({ error: "Failed to delete session" }, { status: 500 });
  }
}
