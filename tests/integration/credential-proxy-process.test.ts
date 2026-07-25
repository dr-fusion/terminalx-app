import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createSecretBrokerClient } from "@/lib/connections/secret-broker-client";
import { createCredentialProxyClient } from "@/lib/connections/credential-proxy-client";
import { secretBrokerExpectationDigest } from "@/lib/connections/secret-broker-shared";
import type { CredentialHandleRegistrationExpectation } from "@/lib/connections/authority";

const REPO_ROOT = path.resolve(__dirname, "../..");
const DAEMON = path.join(REPO_ROOT, "packages/secret-broker/src/daemon.ts");
const HELPER_SOURCE = path.join(
  REPO_ROOT,
  "packages/secret-broker/native/terminalx-secret-broker-peercred.c"
);
const TSX = path.join(REPO_ROOT, "node_modules/.bin/tsx");
const BOT_TOKEN = "998877:AA-Example-Bot-Token";

const temporaryDirectories: string[] = [];
const children: ChildProcess[] = [];
const servers: http.Server[] = [];

function supported(): boolean {
  return (
    process.platform === "linux" &&
    fs.existsSync(TSX) &&
    spawnSync("sh", ["-c", "command -v cc"]).status === 0
  );
}

function temporaryRoot(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "credential-proxy-process-"));
  fs.chmodSync(dir, 0o700);
  temporaryDirectories.push(dir);
  return dir;
}

interface FakeProvider {
  readonly origin: string;
  readonly requests: { url: string; body: string; contentType: string | undefined }[];
}

async function startFakeProvider(): Promise<FakeProvider> {
  const requests: FakeProvider["requests"] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      requests.push({
        url: req.url ?? "",
        body: Buffer.concat(chunks).toString("utf8"),
        contentType: req.headers["content-type"],
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, result: { message_id: 99, date: 123 } }));
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no address");
  return { origin: `http://127.0.0.1:${address.port}`, requests };
}

function writeBootstrap(rootDir: string, providerOrigin: string): string {
  const helper = path.join(rootDir, "peercred");
  const compile = spawnSync("cc", [
    "-std=c17",
    "-O2",
    "-Wall",
    "-Werror",
    HELPER_SOURCE,
    "-o",
    helper,
  ]);
  if (compile.status !== 0) throw new Error("compile failed");
  fs.chmodSync(helper, 0o700);
  const executableSha256 = createHash("sha256").update(fs.readFileSync(helper)).digest("hex");
  const configPath = path.join(rootDir, "bootstrap.json");
  fs.writeFileSync(
    configPath,
    JSON.stringify({
      rootDir,
      expectedOwnerUid: typeof process.geteuid === "function" ? process.geteuid() : 0,
      expectedParentPid: null,
      peercred: { executableFile: helper, executableSha256 },
      adapters: { oauthEnvelope: true },
      receiptTtlMs: 60_000,
      reconcileIntervalMs: 1000,
      proxy: {
        enabled: true,
        originOverrides: { "api.telegram.org": providerOrigin },
        requestTimeoutMs: 5000,
      },
    })
  );
  fs.chmodSync(configPath, 0o600);
  return configPath;
}

async function startDaemon(configPath: string): Promise<ChildProcess> {
  const child = spawn(TSX, [DAEMON, configPath], {
    cwd: REPO_ROOT,
    stdio: ["ignore", "ignore", "pipe"],
  });
  children.push(child);
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("daemon did not become ready")), 30_000);
    let buffer = "";
    child.stderr?.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      if (buffer.includes('"event":"broker.ready"')) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`daemon exited early with code ${code}`));
    });
  });
  return child;
}

async function stop(child: ChildProcess, signal: NodeJS.Signals = "SIGKILL"): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    child.once("exit", () => resolve());
    child.kill(signal);
  });
}

afterEach(async () => {
  while (children.length > 0) await stop(children.pop()!);
  while (servers.length > 0) {
    const server = servers.pop()!;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  while (temporaryDirectories.length > 0) {
    fs.rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

const expectation: CredentialHandleRegistrationExpectation = Object.freeze({
  provider: "telegram",
  brokerKind: "oauth-envelope",
  usage: "installation",
  authorityBinding: Object.freeze({
    kind: "installation",
    teamId: "team_1",
    externalTenantId: "T1",
    externalAppId: "A1",
  }),
  replaces: null,
});

describe("Credential Proxy daemon process", () => {
  it("executes a typed operation over the proxy socket without exposing the credential", async () => {
    if (!supported()) return;
    const rootDir = temporaryRoot();
    const provider = await startFakeProvider();
    await startDaemon(writeBootstrap(rootDir, provider.origin));

    // Register + finalize an oauth-envelope Telegram installation handle.
    const brokerClient = createSecretBrokerClient({
      socketPath: path.join(rootDir, "broker.sock"),
    });
    const receipt = await brokerClient.prepareRegistration(
      expectation,
      Buffer.from(BOT_TOKEN, "utf8")
    );
    await brokerClient.finalizeRegistration(receipt.payload.handleId, receipt.payload.receiptId);
    expect((await brokerClient.handleStatus(receipt.payload.handleId)).status).toBe("active");

    // Execute a typed operation over the sibling proxy socket.
    const proxyClient = createCredentialProxyClient({
      socketPath: path.join(rootDir, "proxy.sock"),
    });
    const result = await proxyClient.execute({
      operation: "telegram.sendMessage",
      authority: {
        provider: "telegram",
        handleId: receipt.payload.handleId,
        handleGeneration: 1,
        expectationDigest: secretBrokerExpectationDigest(expectation),
        installationId: "inst_1",
        installationRevision: 1,
        bindingId: null,
        bindingRevision: null,
      },
      params: { chatId: "1001", text: "hello from 8D" },
    });

    expect(result.resultClass).toBe("ok");
    expect(result.projection).toEqual({ messageId: 99, date: 123 });
    expect(result.accountingRowId).toBeGreaterThan(0);

    // The bot token reached the provider at the effect boundary...
    expect(provider.requests).toHaveLength(1);
    expect(provider.requests[0]!.url).toBe(`/bot${BOT_TOKEN}/sendMessage`);
    expect(JSON.parse(provider.requests[0]!.body)).toEqual({
      chat_id: "1001",
      text: "hello from 8D",
    });
    // ...but never appears in the result returned over the socket.
    expect(JSON.stringify(result)).not.toContain(BOT_TOKEN);
    expect(JSON.stringify(result)).not.toContain("/bot");
  }, 60_000);

  it("fails a stale authority digest closed over the socket, without calling the provider", async () => {
    if (!supported()) return;
    const rootDir = temporaryRoot();
    const provider = await startFakeProvider();
    await startDaemon(writeBootstrap(rootDir, provider.origin));

    const brokerClient = createSecretBrokerClient({
      socketPath: path.join(rootDir, "broker.sock"),
    });
    const receipt = await brokerClient.prepareRegistration(
      expectation,
      Buffer.from(BOT_TOKEN, "utf8")
    );
    await brokerClient.finalizeRegistration(receipt.payload.handleId, receipt.payload.receiptId);

    const proxyClient = createCredentialProxyClient({
      socketPath: path.join(rootDir, "proxy.sock"),
    });
    const result = await proxyClient.execute({
      operation: "telegram.sendMessage",
      authority: {
        provider: "telegram",
        handleId: receipt.payload.handleId,
        handleGeneration: 1,
        expectationDigest: "f".repeat(64),
        installationId: "inst_1",
        installationRevision: 1,
        bindingId: null,
        bindingRevision: null,
      },
      params: { chatId: "1001", text: "should not send" },
    });

    expect(result.resultClass).toBe("denied");
    expect(result.errorCode).toBe("authority-mismatch");
    expect(provider.requests).toHaveLength(0);
  }, 60_000);
});
