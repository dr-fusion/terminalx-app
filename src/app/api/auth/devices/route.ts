import { NextRequest, NextResponse } from "next/server";
import { listDevicesForUser, revokeDevice } from "@/lib/devices";
import { audit } from "@/lib/audit-log";
import { resolveRequestActor } from "@/lib/request-actor";

// GET /api/auth/devices — list paired devices for the current user
// DELETE /api/auth/devices?id=dvc_... — revoke a device

export async function GET(req: NextRequest) {
  const actor = await resolveRequestActor(req.headers);
  if (!actor) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }
  try {
    const devices = listDevicesForUser(actor.userId).map((d) => ({
      id: d.id,
      name: d.name,
      createdAt: d.createdAt,
      lastSeenAt: d.lastSeenAt,
      revokedAt: d.revokedAt,
    }));
    return NextResponse.json({ devices }, { headers: { "Cache-Control": "no-store, max-age=0" } });
  } catch {
    audit("device_registry_read_failed", {
      username: actor.username,
      userId: actor.userId,
    });
    return NextResponse.json(
      { error: "Paired devices are temporarily unavailable. Try again." },
      { status: 503, headers: { "Cache-Control": "no-store, max-age=0" } }
    );
  }
}

export async function DELETE(req: NextRequest) {
  const actor = await resolveRequestActor(req.headers);
  if (!actor) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }
  const deviceId = req.nextUrl.searchParams.get("id");
  if (!deviceId) {
    return NextResponse.json({ error: "Missing device id" }, { status: 400 });
  }
  let ok: boolean;
  try {
    ok = await revokeDevice(deviceId, actor.userId);
  } catch {
    audit("device_revocation_failed", {
      username: actor.username,
      userId: actor.userId,
      detail: deviceId,
    });
    return NextResponse.json(
      { error: "Device revocation could not be completed safely. Try again." },
      { status: 503, headers: { "Cache-Control": "no-store, max-age=0" } }
    );
  }
  if (!ok) {
    return NextResponse.json({ error: "Device not found" }, { status: 404 });
  }
  audit("device_revoked", {
    username: actor.username,
    userId: actor.userId,
    detail: deviceId,
  });
  return NextResponse.json(
    { success: true },
    { headers: { "Cache-Control": "no-store, max-age=0" } }
  );
}
