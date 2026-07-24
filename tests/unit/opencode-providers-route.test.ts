import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { repoSettingsPath, readOpenCodeProviderConfig } from "@/lib/harnesses/settings-toml";

// ── request mocks (mirrors diffs-route.test.ts) ──────────────────────────────
function mockGet(search: Record<string, string> = {}, headers: Record<string, string> = {}) {
  const params = new URLSearchParams(search);
  return {
    headers: { get: (n: string) => headers[n.toLowerCase()] ?? null },
    nextUrl: { searchParams: params },
  } as never;
}

function mockBody(body: unknown, headers: Record<string, string> = {}) {
  return {
    headers: { get: (n: string) => headers[n.toLowerCase()] ?? null },
    json: async () => body,
    nextUrl: { searchParams: new URLSearchParams() },
  } as never;
}

async function loadRoute() {
  return await import("@/app/api/harnesses/opencode/providers/route");
}

describe("GET /api/harnesses/opencode/providers", () => {
  beforeEach(() => {
    process.env.TERMINALX_AUTH_MODE = "none";
    process.env.TERMINALX_ALLOW_AUTH_NONE = "true";
  });
  afterEach(() => {
    delete process.env.TERMINALX_AUTH_MODE;
    delete process.env.TERMINALX_ALLOW_AUTH_NONE;
  });

  it("returns the 7 featured rows + total 96 by default", async () => {
    const { GET } = await loadRoute();
    const res = await GET(mockGet());
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.count).toBe(96);
    expect(body.featured).toHaveLength(7);
    expect(body.featured[0].id).toBe("opencode-zen");
    // default view does not dump all 96
    expect(body.providers).toBeUndefined();
  });

  it("?all=1 returns the full 96-entry catalog", async () => {
    const { GET } = await loadRoute();
    const res = await GET(mockGet({ all: "1" }));
    const body = await res.json();
    expect(body.providers).toHaveLength(96);
    expect(body.count).toBe(96);
  });

  it("?all=1&q=openrouter filters across the catalog", async () => {
    const { GET } = await loadRoute();
    const res = await GET(mockGet({ all: "1", q: "openrouter" }));
    const body = await res.json();
    expect(body.providers.map((p: { id: string }) => p.id)).toContain("openrouter");
    expect(body.count).toBe(body.providers.length);
  });
});

describe("POST/DELETE /api/harnesses/opencode/providers (repo scope, fs)", () => {
  let root: string;
  let repoRoot: string;

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "tx-oc-route-")));
    process.env.TERMINUS_ROOT = root;
    process.env.TERMINALX_AUTH_MODE = "none";
    process.env.TERMINALX_ALLOW_AUTH_NONE = "true";
    repoRoot = path.join(root, "repo");
    fs.mkdirSync(repoRoot, { recursive: true });
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    delete process.env.TERMINUS_ROOT;
    delete process.env.TERMINALX_AUTH_MODE;
    delete process.env.TERMINALX_ALLOW_AUTH_NONE;
  });

  it("POST persists a provider to .terminalx/settings.toml (repo scope) and increments the count", async () => {
    const { POST } = await loadRoute();
    const res = await POST(
      mockBody({ providerId: "anthropic", models: ["claude-opus-4-8"], scope: "repo", repoRoot })
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.providers).toEqual(["anthropic"]);

    const raw = fs.readFileSync(repoSettingsPath(repoRoot), "utf-8");
    expect(raw).toContain("[harness.opencode]");
    expect(raw).toContain("anthropic");
    // a second provider increments to 2
    const res2 = await POST(mockBody({ providerId: "openrouter", scope: "repo", repoRoot }));
    const body2 = await res2.json();
    expect(body2.providers).toEqual(["anthropic", "openrouter"]);
  });

  it("POST rejects an unknown provider id with 400", async () => {
    const { POST } = await loadRoute();
    const res = await POST(
      mockBody({ providerId: "not-a-real-provider", scope: "repo", repoRoot })
    );
    expect(res.status).toBe(400);
  });

  it("POST never writes a secret to the committed file (AC-7/AC-10)", async () => {
    const { POST } = await loadRoute();
    await POST(
      mockBody({
        providerId: "openrouter",
        apiKey: "sk-leak",
        token: "ghp_leak",
        scope: "repo",
        repoRoot,
      })
    );
    const raw = fs.readFileSync(repoSettingsPath(repoRoot), "utf-8");
    expect(raw).not.toContain("sk-leak");
    expect(raw).not.toContain("ghp_leak");
    expect(raw.toLowerCase()).not.toContain("apikey");
  });

  it("POST validates a gateway endpoint must be https/localhost", async () => {
    const { POST } = await loadRoute();
    const bad = await POST(
      mockBody({
        providerId: "openrouter",
        endpoint: "ftp://evil.example.com",
        scope: "repo",
        repoRoot,
      })
    );
    expect(bad.status).toBe(400);
    const ok = await POST(
      mockBody({
        providerId: "openrouter",
        endpoint: "https://gw.example.com/v1",
        scope: "repo",
        repoRoot,
      })
    );
    expect(ok.status).toBe(200);
  });

  it("GET ?configured=1 reports the scoped configured providers + counts", async () => {
    const { GET, POST } = await loadRoute();
    await POST(
      mockBody({ providerId: "anthropic", models: ["claude-opus-4-8"], scope: "repo", repoRoot })
    );
    const res = await GET(mockGet({ configured: "1", scope: "repo", repoRoot }));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.providers).toEqual(["anthropic"]);
    expect(body.configuredCount).toBe(1);
    expect(body.selectedModelCount).toBe(1);
  });

  it("DELETE removes a configured provider", async () => {
    const { POST, DELETE } = await loadRoute();
    await POST(mockBody({ providerId: "anthropic", scope: "repo", repoRoot }));
    await POST(mockBody({ providerId: "openrouter", scope: "repo", repoRoot }));
    expect(readOpenCodeProviderConfig(repoRoot).providers).toHaveLength(2);

    const res = await DELETE(mockGet({ providerId: "anthropic", scope: "repo", repoRoot }));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.providers).toEqual(["openrouter"]);
    expect(readOpenCodeProviderConfig(repoRoot).providers).toEqual(["openrouter"]);
  });

  it("POST 403s when repoRoot escapes TERMINUS_ROOT", async () => {
    const { POST } = await loadRoute();
    const outside = fs.realpathSync(os.tmpdir());
    const res = await POST(mockBody({ providerId: "anthropic", scope: "repo", repoRoot: outside }));
    expect(res.status).toBe(403);
  });
});
