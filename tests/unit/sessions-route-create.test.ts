import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const mocks = vi.hoisted(() => ({
  listSessions: vi.fn(),
  createSession: vi.fn(),
  killSession: vi.fn(),
  getUserScoping: vi.fn(),
  canAccessSession: vi.fn(),
  scopedSessionName: vi.fn(),
  audit: vi.fn(),
  listMetadata: vi.fn(),
  saveMeta: vi.fn(),
  deleteMeta: vi.fn(),
  getMeta: vi.fn(),
  commandForKind: vi.fn(),
  isValidKind: vi.fn(),
  ensureManagedSession: vi.fn(),
  listHarnesses: vi.fn(),
  getHarness: vi.fn(),
  resolveSessionModelSettings: vi.fn(),
  modelOptionsForKind: vi.fn(),
  listTopics: vi.fn(),
  botIsConfigured: vi.fn(),
  ensureTopicForSession: vi.fn(),
  getEnsureTopic: vi.fn(),
  getConfiguredMaxSessions: vi.fn(),
  assertNotSensitivePath: vi.fn(),
  resolveSafePath: vi.fn(),
  createGitWorktreeForSession: vi.fn(),
  removeGitWorktree: vi.fn(),
  resolveWorkspaceConfig: vi.fn(),
  copyConfiguredFiles: vi.fn(),
  allocateWorkspacePort: vi.fn(),
  withWorkspaceEnv: vi.fn(),
  runSetup: vi.fn(),
  bridgedEnsureTopic: vi.fn(),
}));

vi.mock("@/lib/tmux", () => ({
  listSessions: mocks.listSessions,
  createSession: mocks.createSession,
  killSession: mocks.killSession,
}));

vi.mock("@/lib/session-scope", () => ({
  getUserScoping: mocks.getUserScoping,
  canAccessSession: mocks.canAccessSession,
  scopedSessionName: mocks.scopedSessionName,
}));

vi.mock("@/lib/audit-log", () => ({ audit: mocks.audit }));

vi.mock("@/lib/ai-sessions", () => ({
  listMetadata: mocks.listMetadata,
  saveMeta: mocks.saveMeta,
  deleteMeta: mocks.deleteMeta,
  getMeta: mocks.getMeta,
  commandForKind: mocks.commandForKind,
  isValidKind: mocks.isValidKind,
  ensureManagedSession: mocks.ensureManagedSession,
}));

vi.mock("@/lib/harnesses/registry", () => ({
  listHarnesses: mocks.listHarnesses,
  getHarness: mocks.getHarness,
}));

vi.mock("@/lib/settings/session-settings", () => ({
  resolveSessionModelSettings: mocks.resolveSessionModelSettings,
}));

vi.mock("@/lib/harnesses/session-model", () => ({
  modelOptionsForKind: mocks.modelOptionsForKind,
}));

vi.mock("@/lib/telegram/state", () => ({ listTopics: mocks.listTopics }));

vi.mock("@/lib/telegram/auth", () => ({ botIsConfigured: mocks.botIsConfigured }));

vi.mock("@/lib/telegram/bot", () => ({
  ensureTopicForSession: mocks.ensureTopicForSession,
}));

vi.mock("@/lib/telegram/bot-bridge", () => ({
  getEnsureTopic: mocks.getEnsureTopic,
}));

vi.mock("@/lib/security-config", () => ({
  getConfiguredMaxSessions: mocks.getConfiguredMaxSessions,
}));

vi.mock("@/lib/file-service", () => ({
  assertNotSensitivePath: mocks.assertNotSensitivePath,
  resolveSafePath: mocks.resolveSafePath,
}));

vi.mock("@/lib/git-worktree", () => ({
  createGitWorktreeForSession: mocks.createGitWorktreeForSession,
  removeGitWorktree: mocks.removeGitWorktree,
}));

vi.mock("@/lib/workspace-config", () => ({
  resolveWorkspaceConfig: mocks.resolveWorkspaceConfig,
  copyConfiguredFiles: mocks.copyConfiguredFiles,
}));

vi.mock("@/lib/workspace-port", () => ({
  allocateWorkspacePort: mocks.allocateWorkspacePort,
}));

vi.mock("@/lib/workspace-setup", () => ({
  withWorkspaceEnv: mocks.withWorkspaceEnv,
  runSetup: mocks.runSetup,
}));

function mockReq(body: unknown) {
  return {
    headers: { get: () => null },
    json: async () => body,
  } as never;
}

describe("POST /api/sessions", () => {
  let tmpDir = "";

  beforeEach(() => {
    vi.resetModules();
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "tx-session-route-")));

    for (const fn of Object.values(mocks)) fn.mockReset();
    mocks.listSessions.mockReturnValue([]);
    mocks.getUserScoping.mockReturnValue({
      username: "admin",
      role: "admin",
      shouldScope: false,
      hasIdentity: true,
    });
    mocks.scopedSessionName.mockImplementation((name: string) => name);
    mocks.getConfiguredMaxSessions.mockReturnValue(20);
    mocks.resolveSafePath.mockReturnValue(tmpDir);
    mocks.isValidKind.mockReturnValue(true);
    mocks.commandForKind.mockReturnValue("codex");
    mocks.listMetadata.mockReturnValue([]);
    mocks.resolveSessionModelSettings.mockReturnValue({
      modelId: "claude:opus-4-8-1m",
      effort: "high",
      personality: "pragmatic",
      planMode: false,
      fastMode: false,
      modelExplicit: false,
    });
    mocks.modelOptionsForKind.mockReturnValue({ planMode: false, model: undefined });
    mocks.getHarness.mockReturnValue({ command: { bin: "codex" } });
    mocks.allocateWorkspacePort.mockResolvedValue(4100);
    mocks.resolveWorkspaceConfig.mockReturnValue({
      copyFiles: [],
      env: {},
      setup: null,
    });
    mocks.withWorkspaceEnv.mockImplementation((inner: string) => inner);
    mocks.listTopics.mockReturnValue([]);
    mocks.botIsConfigured.mockReturnValue(true);
    mocks.getEnsureTopic.mockReturnValue(mocks.bridgedEnsureTopic);
    mocks.bridgedEnsureTopic.mockImplementation(async (_identity, sessionName, viewMode) => ({
      topic: {
        topicId: 42,
        sessionName,
        viewMode,
        url: "https://t.me/c/1/42",
        created: true,
      },
    }));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.TERMINUS_READ_ONLY;
  });

  it("auto-creates a Telegram topic in chat mode when Telegram is configured", async () => {
    const { POST } = await import("@/app/api/sessions/route");
    const res = await POST(mockReq({ name: "agent", kind: "codex", cwd: tmpDir }));
    const body = await res.json();

    expect(res.status).toBe(201);
    expect(mocks.commandForKind).toHaveBeenCalledWith("codex", {
      planMode: false,
      model: undefined,
    });
    expect(mocks.createSession).toHaveBeenCalledWith("agent", "codex", tmpDir);
    expect(mocks.saveMeta).toHaveBeenCalledWith(
      expect.objectContaining({ name: "agent", modelId: undefined })
    );
    expect(mocks.bridgedEnsureTopic).toHaveBeenCalledWith(
      { username: "admin", role: "admin" },
      "agent",
      "chat"
    );
    expect(body.telegram).toMatchObject({
      topicId: 42,
      sessionName: "agent",
      viewMode: "chat",
      created: true,
    });
  });

  it("persists only the validated model passed to the harness", async () => {
    mocks.resolveSessionModelSettings.mockReturnValue({
      modelId: "codex:gpt-5-codex",
      effort: "high",
      personality: "pragmatic",
      planMode: false,
      fastMode: false,
      modelExplicit: true,
    });
    mocks.modelOptionsForKind.mockReturnValue({ planMode: false, model: "gpt-5-codex" });

    const { POST } = await import("@/app/api/sessions/route");
    const res = await POST(mockReq({ name: "model-session", kind: "codex", cwd: tmpDir }));

    expect(res.status).toBe(201);
    expect(mocks.saveMeta).toHaveBeenCalledWith(
      expect.objectContaining({ name: "model-session", modelId: "codex:gpt-5-codex" })
    );
  });

  it("rejects permission skipping before any session or worktree effect", async () => {
    const { POST } = await import("@/app/api/sessions/route");
    const res = await POST(
      mockReq({
        name: "agent",
        kind: "claude",
        cwd: tmpDir,
        dangerouslySkipPermissions: true,
        worktree: { create: true, branch: "feature/unsafe" },
      })
    );
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body).toEqual({
      error:
        "LocalTmux sessions cannot skip harness permissions; dangerouslySkipPermissions is not allowed",
    });
    expect(mocks.getUserScoping).not.toHaveBeenCalled();
    expect(mocks.listSessions).not.toHaveBeenCalled();
    expect(mocks.resolveSafePath).not.toHaveBeenCalled();
    expect(mocks.createGitWorktreeForSession).not.toHaveBeenCalled();
    expect(mocks.allocateWorkspacePort).not.toHaveBeenCalled();
    expect(mocks.commandForKind).not.toHaveBeenCalled();
    expect(mocks.createSession).not.toHaveBeenCalled();
    expect(mocks.saveMeta).not.toHaveBeenCalled();
  });

  it("surfaces a main refresh failure without creating the session", async () => {
    mocks.createGitWorktreeForSession.mockImplementation(() => {
      throw new Error(
        "Failed to refresh main before creating Git worktree: fatal: unable to access origin"
      );
    });

    const { POST } = await import("@/app/api/sessions/route");
    const res = await POST(
      mockReq({
        name: "agent",
        kind: "codex",
        cwd: tmpDir,
        worktree: { create: true, branch: "feature/refresh-failure" },
      })
    );
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body).toEqual({
      error: "Failed to refresh main before creating Git worktree: fatal: unable to access origin",
    });
    expect(mocks.allocateWorkspacePort).not.toHaveBeenCalled();
    expect(mocks.createSession).not.toHaveBeenCalled();
    expect(mocks.saveMeta).not.toHaveBeenCalled();
  });
});
