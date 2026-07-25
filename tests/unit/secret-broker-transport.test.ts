import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { establishBrokerRoot } from "../../packages/secret-broker/src/broker-root";
import { createSecretBroker } from "../../packages/secret-broker/src/broker";
import { createOauthEnvelopeAdapter } from "../../packages/secret-broker/src/adapters/oauth-envelope";
import { openSecretBrokerStateStore } from "../../packages/secret-broker/src/state-store";
import {
  startSecretBrokerUnixServer,
  type SecretBrokerDenialEvent,
  type SecretBrokerUnixServer,
} from "../../packages/secret-broker/src/unix-socket-transport";
import {
  createPinnedPeerCredentialVerifier,
  type SecretBrokerPeerCredentialVerifier,
} from "../../packages/secret-broker/src/peer-credentials";
import { createSecretBrokerClient } from "@/lib/connections/secret-broker-client";

const HELPER_SOURCE = path.resolve(
  __dirname,
  "../../packages/secret-broker/native/terminalx-secret-broker-peercred.c"
);
const temporaryDirectories: string[] = [];
const servers: SecretBrokerUnixServer[] = [];

function temporaryRoot(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secret-broker-transport-"));
  fs.chmodSync(dir, 0o700);
  temporaryDirectories.push(dir);
  return dir;
}
afterEach(async () => {
  while (servers.length > 0) await servers.pop()!.close();
  while (temporaryDirectories.length > 0) {
    fs.rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

function brokerFor(rootDir: string) {
  const root = establishBrokerRoot({ rootDir });
  const store = openSecretBrokerStateStore({ databasePath: root.databasePath });
  const broker = createSecretBroker({
    root,
    store,
    adapters: { "oauth-envelope": createOauthEnvelopeAdapter(root.atRestKey) },
  });
  return { root, broker };
}

async function start(
  rootDir: string,
  verify: SecretBrokerPeerCredentialVerifier,
  onDenial?: (event: SecretBrokerDenialEvent) => void
): Promise<{ socketPath: string }> {
  const { root, broker } = brokerFor(rootDir);
  const server = await startSecretBrokerUnixServer({
    socketPath: root.socketPath,
    verifyPeerCredentials: verify,
    handler: broker.handle,
    onDenial,
  });
  servers.push(server);
  return { socketPath: server.socketPath };
}

function currentUid(): number {
  return typeof process.geteuid === "function" ? process.geteuid() : 0;
}

describe("Secret Broker unix transport", () => {
  it("admits a same-uid peer and serves broker.health", async () => {
    const { socketPath } = await start(temporaryRoot(), async () => ({
      pid: process.pid,
      uid: currentUid(),
      gid: 0,
    }));
    const client = createSecretBrokerClient({ socketPath });
    expect((await client.health()).pendingRegistrations).toBe(0);
  });

  it("rejects a wrong-uid peer and audits the denial", async () => {
    const denials: SecretBrokerDenialEvent[] = [];
    const { socketPath } = await start(
      temporaryRoot(),
      async () => ({ pid: process.pid, uid: currentUid() + 99999, gid: 0 }),
      (event) => denials.push(event)
    );
    const client = createSecretBrokerClient({ socketPath, requestTimeoutMs: 2000 });
    await expect(client.health()).rejects.toMatchObject({ code: "unavailable" });
    expect(denials).toContainEqual({ reason: "peer-credentials", code: "permission-denied" });
  });

  it("verifies real SO_PEERCRED with the pinned helper", async () => {
    if (process.platform !== "linux") return;
    if (spawnSync("sh", ["-c", "command -v cc"]).status !== 0) return;
    const rootDir = temporaryRoot();
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
    if (compile.status !== 0) return;
    fs.chmodSync(helper, 0o700);
    const executableSha256 = createHash("sha256").update(fs.readFileSync(helper)).digest("hex");
    const verify = createPinnedPeerCredentialVerifier({ executableFile: helper, executableSha256 });
    const { socketPath } = await start(rootDir, verify);
    const client = createSecretBrokerClient({ socketPath });
    // The connecting peer is this same-uid test process, so SO_PEERCRED admits it.
    expect((await client.health()).pendingRegistrations).toBe(0);
  });

  it("rejects a group-writable (unpinned) helper", async () => {
    if (process.platform !== "linux") return;
    if (spawnSync("sh", ["-c", "command -v cc"]).status !== 0) return;
    const rootDir = temporaryRoot();
    const helper = path.join(rootDir, "peercred");
    if (spawnSync("cc", ["-std=c17", HELPER_SOURCE, "-o", helper]).status !== 0) return;
    fs.chmodSync(helper, 0o775); // group-writable: must be refused
    const executableSha256 = createHash("sha256").update(fs.readFileSync(helper)).digest("hex");
    expect(() =>
      createPinnedPeerCredentialVerifier({ executableFile: helper, executableSha256 })
    ).toThrow();
  });
});
