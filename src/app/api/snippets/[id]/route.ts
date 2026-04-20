import { NextRequest, NextResponse } from "next/server";
import { deleteSnippet, getSnippet } from "@/lib/snippets";
import { getUserScoping } from "@/lib/session-scope";
import { audit } from "@/lib/audit-log";

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  if (process.env.TERMINUS_READ_ONLY === "true") {
    return NextResponse.json(
      { error: "Snippet deletion disabled in read-only mode" },
      { status: 403 }
    );
  }
  try {
    const { id } = await params;
    const snippet = getSnippet(id);
    if (!snippet) {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }

    const { username, role, shouldScope } = getUserScoping(req.headers);
    if (
      shouldScope &&
      role !== "admin" &&
      snippet.createdBy &&
      snippet.createdBy !== username
    ) {
      return NextResponse.json(
        { error: "Cannot delete another user's snippet" },
        { status: 403 }
      );
    }

    await deleteSnippet(id);
    audit("snippet_deleted", { username: username || undefined, detail: id });
    return NextResponse.json({ success: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to delete snippet";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
