import { NextRequest, NextResponse } from "next/server";
// Issue #4 + #8: /api/harnesses/opencode/providers — the OpenCode "Providers"
// picker backend.
//
//   GET                       → featured 7 + total 96 (the picker's initial view)
//   GET ?all=1&q=<term>       → the full 96-entry catalog, filtered by search
//   POST { providerId, ... }  → persist the provider stanza into the scoped
//                               .terminalx/settings.toml ([harness.opencode]
//                               providers/models keys, NON-SECRET only)
//   DELETE ?providerId=&scope=&repoRoot= → un-configure a provider
//
// These are OpenCode's OWN providers: persisting one only records the non-secret
// config that OpenCode's CLI later reads. TerminalX never holds or proxies a
// provider secret (spec §6, AC-7/AC-10) — there is NO credential vault here.
import {
  FEATURED_OPENCODE_PROVIDERS,
  TOTAL_OPENCODE_PROVIDERS,
  getProviderEntry,
  searchProviders,
} from "@/lib/harnesses/opencode-providers";
import {
  readOpenCodeProviderConfig,
  removeOpenCodeProviderConfig,
  writeOpenCodeProviderConfig,
} from "@/lib/harnesses/settings-toml";
import { canAccessSession } from "@/lib/session-scope";
import { assertNotSensitivePath, resolveSafePath } from "@/lib/file-service";
import { resolveSessionWorkspace } from "@/lib/workspace-resolve";
import { audit } from "@/lib/audit-log";
import { resolveRequestActor } from "@/lib/request-actor";

type Scope = "user" | "repo";

function isScope(v: unknown): v is Scope {
  return v === "user" || v === "repo";
}

/**
 * Validate a gateway endpoint URL: https only (allow http://localhost for dev),
 * matching the spec's §11 "Untrusted gateway URL" mitigation. TerminalX never
 * connects to it; this just keeps obviously-bad values out of the committed file.
 */
function endpointError(endpoint: string): string | null {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return "endpoint must be a valid URL";
  }
  if (url.protocol === "https:") return null;
  if (url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1")) {
    return null;
  }
  return "endpoint must be https:// (or http://localhost for development)";
}

/**
 * Resolve the repo root from the request for repo-scoped writes, confined to
 * TERMINUS_ROOT (reuses the sessions/diffs route path guards). The client may
 * pass either an explicit `repoRoot` OR a `session` name we resolve server-side
 * (mirrors /api/workspace/config/raw). User scope needs no repoRoot. Throws an
 * Error whose message the catch maps to 403.
 */
function resolveRepoRoot(
  scope: Scope,
  source: { repoRoot?: unknown; session?: unknown },
  caller: { username: string | null; role: string | null }
): string | undefined {
  if (scope !== "repo") return undefined;

  if (typeof source.session === "string" && source.session) {
    if (!canAccessSession(caller.username, caller.role, source.session)) {
      throw new Error("Access denied to sensitive path");
    }
    const workspace = resolveSessionWorkspace(source.session);
    if (!workspace) throw new Error("repoRoot is required for repo scope");
    const safe = resolveSafePath(workspace.repoRoot);
    assertNotSensitivePath(safe);
    return safe;
  }

  if (typeof source.repoRoot !== "string" || !source.repoRoot) {
    throw new Error("repoRoot is required for repo scope");
  }
  const safe = resolveSafePath(source.repoRoot);
  assertNotSensitivePath(safe);
  return safe;
}

export async function GET(req: NextRequest) {
  try {
    const params = req.nextUrl?.searchParams ?? new URLSearchParams();
    const all = params.get("all") === "1";
    const configured = params.get("configured") === "1";
    const q = params.get("q") ?? "";

    // ?configured=1 → the user/repo-scoped configured providers + counts that
    // back the OpenCode panel's "N configured" / "N selected" labels.
    if (configured) {
      const actor = await resolveRequestActor(req.headers);
      if (!actor) {
        return NextResponse.json({ error: "Access denied" }, { status: 403 });
      }
      const scope: Scope = isScope(params.get("scope")) ? (params.get("scope") as Scope) : "repo";
      let repoRoot: string | undefined;
      try {
        repoRoot = resolveRepoRoot(
          scope,
          { repoRoot: params.get("repoRoot"), session: params.get("session") },
          { username: actor.username, role: actor.legacyRole }
        );
      } catch {
        // No resolvable repo (e.g. no worktree-backed session yet) → empty, not an error.
        return NextResponse.json({
          providers: [],
          models: [],
          configuredCount: 0,
          selectedModelCount: 0,
        });
      }
      const config = readOpenCodeProviderConfig(repoRoot, scope);
      return NextResponse.json({
        providers: config.providers,
        models: config.models,
        endpoints: config.endpoints,
        configuredCount: config.providers.length,
        selectedModelCount: config.models.length,
      });
    }

    if (all) {
      const providers = searchProviders(q);
      return NextResponse.json({ count: providers.length, providers });
    }

    return NextResponse.json({
      count: TOTAL_OPENCODE_PROVIDERS,
      featured: FEATURED_OPENCODE_PROVIDERS,
    });
  } catch (err) {
    console.error("[api/harnesses/opencode/providers GET]", err);
    return NextResponse.json({ error: "Failed to list providers" }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  if (process.env.TERMINUS_READ_ONLY === "true") {
    return NextResponse.json(
      { error: "Provider config disabled in read-only mode" },
      { status: 403 }
    );
  }

  const actor = await resolveRequestActor(req.headers);
  if (!actor) {
    return NextResponse.json({ error: "Access denied" }, { status: 403 });
  }

  let body: {
    providerId?: unknown;
    endpoint?: unknown;
    models?: unknown;
    scope?: unknown;
    repoRoot?: unknown;
    session?: unknown;
  };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const providerId = body.providerId;
  if (typeof providerId !== "string" || !getProviderEntry(providerId)) {
    return NextResponse.json({ error: "Unknown provider" }, { status: 400 });
  }
  const entry = getProviderEntry(providerId)!;
  const scope: Scope = isScope(body.scope) ? body.scope : "repo";

  // Endpoint is only honoured for gateway providers; validated when present.
  let endpoint: string | undefined;
  if (entry.endpointEditable && typeof body.endpoint === "string" && body.endpoint.trim()) {
    const e = body.endpoint.trim();
    const err = endpointError(e);
    if (err) return NextResponse.json({ error: err }, { status: 400 });
    endpoint = e;
  }

  // Models: accept a string[] of non-empty ids only.
  let models: string[] | undefined;
  if (Array.isArray(body.models)) {
    models = body.models.filter((m): m is string => typeof m === "string" && m.trim().length > 0);
  }

  try {
    const repoRoot = resolveRepoRoot(scope, body, {
      username: actor.username,
      role: actor.legacyRole,
    });
    // NB: apiKey/token/etc are intentionally NOT read off the body — TerminalX
    // persists no secret (AC-7/AC-10); only the non-secret instance is written.
    writeOpenCodeProviderConfig({ providerId, endpoint, models, scope }, repoRoot);
    const config = readOpenCodeProviderConfig(repoRoot, scope);
    audit("opencode_provider_configured", {
      username: actor.username,
      userId: actor.userId,
      detail: `${providerId} (${scope})`,
    });
    return NextResponse.json({
      success: true,
      providers: config.providers,
      models: config.models,
      endpoints: config.endpoints,
      configuredCount: config.providers.length,
      selectedModelCount: config.models.length,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (
      message.includes("outside the allowed root") ||
      message.includes("sensitive path") ||
      message.includes("required for repo scope")
    ) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }
    console.error("[api/harnesses/opencode/providers POST]", err);
    return NextResponse.json({ error: "Failed to save provider" }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  if (process.env.TERMINUS_READ_ONLY === "true") {
    return NextResponse.json(
      { error: "Provider config disabled in read-only mode" },
      { status: 403 }
    );
  }

  const actor = await resolveRequestActor(req.headers);
  if (!actor) {
    return NextResponse.json({ error: "Access denied" }, { status: 403 });
  }

  const params = req.nextUrl?.searchParams ?? new URLSearchParams();
  const providerId = params.get("providerId");
  if (!providerId) {
    return NextResponse.json({ error: "providerId is required" }, { status: 400 });
  }
  const scopeParam = params.get("scope");
  const scope: Scope = isScope(scopeParam) ? scopeParam : "repo";

  try {
    const repoRoot = resolveRepoRoot(
      scope,
      { repoRoot: params.get("repoRoot"), session: params.get("session") },
      { username: actor.username, role: actor.legacyRole }
    );
    removeOpenCodeProviderConfig(providerId, repoRoot, scope);
    const config = readOpenCodeProviderConfig(repoRoot, scope);
    audit("opencode_provider_removed", {
      username: actor.username,
      userId: actor.userId,
      detail: `${providerId} (${scope})`,
    });
    return NextResponse.json({
      success: true,
      providers: config.providers,
      models: config.models,
      endpoints: config.endpoints,
      configuredCount: config.providers.length,
      selectedModelCount: config.models.length,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (
      message.includes("outside the allowed root") ||
      message.includes("sensitive path") ||
      message.includes("required for repo scope")
    ) {
      return NextResponse.json({ error: "Access denied" }, { status: 403 });
    }
    console.error("[api/harnesses/opencode/providers DELETE]", err);
    return NextResponse.json({ error: "Failed to remove provider" }, { status: 500 });
  }
}
