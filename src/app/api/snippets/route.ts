import { NextRequest, NextResponse } from "next/server";
import { listSnippets, createSnippet } from "@/lib/snippets";
import { getUserScoping } from "@/lib/session-scope";
import { audit } from "@/lib/audit-log";

export async function GET(req: NextRequest) {
  try {
    const { username, shouldScope } = getUserScoping(req.headers);
    let snippets = listSnippets();
    if (shouldScope && username) {
      snippets = snippets.filter((s) => !s.createdBy || s.createdBy === username);
    }
    return NextResponse.json({ snippets });
  } catch (err) {
    console.error("[api/snippets GET]", err);
    return NextResponse.json({ error: "Failed to list snippets" }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  if (process.env.TERMINUS_READ_ONLY === "true") {
    return NextResponse.json(
      { error: "Snippet creation disabled in read-only mode" },
      { status: 403 }
    );
  }
  try {
    const body = await req.json();
    const { name, command, description } = body;
    if (typeof name !== "string" || typeof command !== "string") {
      return NextResponse.json({ error: "name and command are required strings" }, { status: 400 });
    }
    if (description !== undefined && typeof description !== "string") {
      return NextResponse.json({ error: "description must be a string" }, { status: 400 });
    }
    const username = req.headers.get("x-username") || undefined;
    const snippet = await createSnippet({
      name,
      command,
      description,
      createdBy: username,
    });
    audit("snippet_created", { username, detail: snippet.name });
    return NextResponse.json({ snippet }, { status: 201 });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to create snippet";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
