import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createSecretBrokerClient } from "@/lib/connections/secret-broker-client";
import {
  createBrokerReceiptVerifier,
  readBrokerVerificationKey,
} from "@/lib/connections/secret-broker-verifier";
import type { CredentialHandleRegistrationExpectation } from "@/lib/connections/authority";

const REPO_ROOT = path.resolve(__dirname, "../..");
const DAEMON = path.join(REPO_ROOT, "packages/secret-broker/src/daemon.ts");
const HELPER_SOURCE = path.join(
  REPO_ROOT,
  "packages/secret-broker/native/terminalx-secret-broker-peercred.c"
);
const TSX = path.join(REPO_ROOT, "node_modules/.bin/tsx");

const temporaryDirectories: string[] = [];
const children: ChildProcess[] = [];

function supported(): boolean {
  return (
    process.platform === "linux" &&
    fs.existsSync(TSX) &&
    spawnSync("sh", ["-c", "command -v cc"]).status === 0
  );
}

function temporaryRoot(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secret-broker-process-"));
  fs.chmodSync(dir, 0o700);
  temporaryDirectories.push(dir);
  return dir;
}

function writeBootstrap(rootDir: string): string {
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

async function stop(child: ChildProcess, signal: NodeJS.Signals = "SIGTERM"): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    child.once("exit", () => resolve());
    child.kill(signal);
  });
}

afterEach(async () => {
  while (children.length > 0) await stop(children.pop()!, "SIGKILL");
  while (temporaryDirectories.length > 0) {
    fs.rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

const expectation: CredentialHandleRegistrationExpectation = Object.freeze({
  provider: "slack",
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

describe("Secret Broker daemon process", () => {
  it("runs prepare/finalize end-to-end over the socket and issues a verifiable receipt", async () => {
    if (!supported()) return;
    const rootDir = temporaryRoot();
    await startDaemon(writeBootstrap(rootDir));
    const client = createSecretBrokerClient({ socketPath: path.join(rootDir, "broker.sock") });

    const receipt = await client.prepareRegistration(expectation, Buffer.from("oauth-secret"));
    const verify = createBrokerReceiptVerifier({
      verificationPublicKey: readBrokerVerificationKey(rootDir)!,
    });
    const verified = verify({ proof: receipt, expected: expectation });
    expect(verified).not.toBeNull();
    expect(verified?.handleId).toBe(receipt.payload.handleId);

    await client.finalizeRegistration(receipt.payload.handleId, receipt.payload.receiptId);
    expect((await client.handleStatus(receipt.payload.handleId)).status).toBe("active");
  }, 45_000);

  it("survives kill -9 mid-flow: a prepared registration is durable and converges after restart", async () => {
    if (!supported()) return;
    const rootDir = temporaryRoot();
    const configPath = writeBootstrap(rootDir);
    const first = await startDaemon(configPath);
    const socketPath = path.join(rootDir, "broker.sock");
    let client = createSecretBrokerClient({ socketPath });

    // Prepare, then hard-kill before finalize.
    const receipt = await client.prepareRegistration(expectation, Buffer.from("oauth-secret"));
    await stop(first, "SIGKILL");

    // Restart against the same broker-private state.
    await startDaemon(configPath);
    client = createSecretBrokerClient({ socketPath });
    // The pending row survived the crash, so finalize still converges to active.
    await client.finalizeRegistration(receipt.payload.handleId, receipt.payload.receiptId);
    expect((await client.handleStatus(receipt.payload.handleId)).status).toBe("active");
  }, 60_000);
});
