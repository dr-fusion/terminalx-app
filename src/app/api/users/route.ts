import { NextRequest, NextResponse } from "next/server";
import { getUsers, createUser, deleteUser, getUserById, getUserByUsername, updateUserRole } from "@/lib/users";
import { getAuthMode } from "@/lib/auth-config";
import { audit } from "@/lib/audit-log";

function isAdmin(req: NextRequest): boolean {
  return req.headers.get("x-user-role") === "admin";
}

const USERNAME_REGEX = /^[a-zA-Z0-9_.]+$/;

export async function GET(req: NextRequest) {
  const authMode = getAuthMode();
  if (authMode !== "local") {
    return NextResponse.json(
      { error: "User management requires local auth mode" },
      { status: 400 }
    );
  }

  if (!isAdmin(req)) {
    return NextResponse.json({ error: "Admin access required" }, { status: 403 });
  }

  const users = getUsers().map(({ passwordHash: _pw, ...u }) => u);
  return NextResponse.json({ users });
}

export async function POST(req: NextRequest) {
  const authMode = getAuthMode();
  if (authMode !== "local") {
    return NextResponse.json(
      { error: "User management requires local auth mode" },
      { status: 400 }
    );
  }

  if (!isAdmin(req)) {
    return NextResponse.json({ error: "Admin access required" }, { status: 403 });
  }

  let body: { username?: string; password?: string; role?: "admin" | "user" };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { username, password, role } = body;

  if (!username || typeof username !== "string") {
    return NextResponse.json({ error: "Username is required" }, { status: 400 });
  }

  if (!USERNAME_REGEX.test(username)) {
    return NextResponse.json(
      { error: "Username may only contain letters, numbers, underscores, and dots" },
      { status: 400 }
    );
  }

  if (!password || typeof password !== "string" || password.length < 8) {
    return NextResponse.json(
      { error: "Password is required (min 8 characters)" },
      { status: 400 }
    );
  }

  if (role && role !== "admin" && role !== "user") {
    return NextResponse.json(
      { error: "Role must be 'admin' or 'user'" },
      { status: 400 }
    );
  }

  try {
    const user = await createUser(username, password, role || "user");
    audit("user_created", {
      username: req.headers.get("x-username") || undefined,
      detail: `created user: ${username} (${role || "user"})`,
    });
    return NextResponse.json({ user }, { status: 201 });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 409 });
  }
}

export async function DELETE(req: NextRequest) {
  const authMode = getAuthMode();
  if (authMode !== "local") {
    return NextResponse.json(
      { error: "User management requires local auth mode" },
      { status: 400 }
    );
  }

  if (!isAdmin(req)) {
    return NextResponse.json({ error: "Admin access required" }, { status: 403 });
  }

  let body: { id?: string; username?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  // Accept either id or username for deletion
  let id = body.id;
  if (!id && body.username) {
    const userByName = getUserByUsername(body.username);
    if (userByName) id = userByName.id;
  }
  if (!id || typeof id !== "string") {
    return NextResponse.json({ error: "User ID or username is required" }, { status: 400 });
  }

  // Prevent deleting the last admin user
  const targetUser = getUserById(id);
  if (targetUser && targetUser.role === "admin") {
    const adminCount = getUsers().filter((u) => u.role === "admin").length;
    if (adminCount <= 1) {
      return NextResponse.json(
        { error: "Cannot delete the last admin user" },
        { status: 400 }
      );
    }
  }

  try {
    await deleteUser(id);
    audit("user_deleted", {
      username: req.headers.get("x-username") || undefined,
      detail: `deleted user id: ${id}`,
    });
    return NextResponse.json({ success: true });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 404 });
  }
}

export async function PATCH(req: NextRequest) {
  const authMode = getAuthMode();
  if (authMode !== "local") {
    return NextResponse.json(
      { error: "User management requires local auth mode" },
      { status: 400 }
    );
  }

  if (!isAdmin(req)) {
    return NextResponse.json({ error: "Admin access required" }, { status: 403 });
  }

  let body: { id?: string; username?: string; role?: "admin" | "user" };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { role } = body;
  if (!role || (role !== "admin" && role !== "user")) {
    return NextResponse.json({ error: "Role must be 'admin' or 'user'" }, { status: 400 });
  }

  // Accept either id or username
  let id = body.id;
  if (!id && body.username) {
    const userByName = getUserByUsername(body.username);
    if (userByName) id = userByName.id;
  }
  if (!id) {
    return NextResponse.json({ error: "User ID or username is required" }, { status: 400 });
  }

  // Prevent demoting the last admin
  const targetUser = getUserById(id);
  if (targetUser && targetUser.role === "admin" && role === "user") {
    const adminCount = getUsers().filter((u) => u.role === "admin").length;
    if (adminCount <= 1) {
      return NextResponse.json(
        { error: "Cannot demote the last admin user" },
        { status: 400 }
      );
    }
  }

  try {
    const updated = await updateUserRole(id, role);
    audit("user_role_changed", {
      username: req.headers.get("x-username") || undefined,
      detail: `changed user ${updated.username} role to ${role}`,
    });
    return NextResponse.json({ user: updated });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 404 });
  }
}
