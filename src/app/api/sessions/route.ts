import { NextRequest, NextResponse } from "next/server";
import {
  listSessions,
  createSession,
  killSession,
} from "@/lib/tmux";

export async function GET() {
  try {
    const sessions = listSessions();
    return NextResponse.json({ sessions });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { name } = body;

    if (!name || typeof name !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid session name" },
        { status: 400 }
      );
    }

    if (!/^[a-zA-Z0-9_.\-]+$/.test(name)) {
      return NextResponse.json(
        { error: "Invalid session name: only alphanumeric, underscore, hyphen, and dot allowed" },
        { status: 400 }
      );
    }

    createSession(name);
    return NextResponse.json({ success: true, name }, { status: 201 });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const body = await req.json();
    const { name } = body;

    if (!name || typeof name !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid session name" },
        { status: 400 }
      );
    }

    killSession(name);
    return NextResponse.json({ success: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
