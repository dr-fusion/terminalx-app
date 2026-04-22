import { NextRequest, NextResponse } from "next/server";
import { killSession } from "@/lib/tmux";
import { getUserScoping, canAccessSession } from "@/lib/session-scope";
import { audit } from "@/lib/audit-log";
import { deleteMeta } from "@/lib/ai-sessions";

interface Ctx {
  params: Promise<{ name: string }>;
}

export async function DELETE(req: NextRequest, ctx: Ctx) {
  if (process.env.TERMINUS_READ_ONLY === "true") {
    return NextResponse.json(
      { error: "Session deletion disabled in read-only mode" },
      { status: 403 }
    );
  }

  try {
    const { name: rawName } = await ctx.params;
    const name = decodeURIComponent(rawName);

    if (!name || !/^[a-zA-Z0-9_.\-]+$/.test(name)) {
      return NextResponse.json({ error: "invalid session name" }, { status: 400 });
    }

    const { username, role, shouldScope } = getUserScoping(req.headers);
    if (shouldScope && username && !canAccessSession(username, role, name)) {
      return NextResponse.json({ error: "cannot delete another user's session" }, { status: 403 });
    }

    killSession(name);
    await deleteMeta(name);
    audit("session_deleted", { username: username || undefined, detail: name });
    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("[api/sessions/:name DELETE]", err);
    return NextResponse.json({ error: "failed to delete session" }, { status: 500 });
  }
}
