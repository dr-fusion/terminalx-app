import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { establishBrokerRoot } from "../../packages/secret-broker/src/broker-root";
import { openSecretBrokerStateStore } from "../../packages/secret-broker/src/state-store";
import { openProxyAccountingStore } from "../../packages/secret-broker/src/proxy/accounting-store";
import { openAtRest, sealAtRest } from "../../packages/secret-broker/src/at-rest";
import {
  createCredentialProxy,
  type CredentialProxy,
  type CredentialProxyAuditEvent,
} from "../../packages/secret-broker/src/proxy/credential-proxy";
import type {
  ProxyNetworkClient,
  ProxyOutboundRequest,
} from "../../packages/secret-broker/src/proxy/network-client";
import { ProxyNetworkError } from "../../packages/secret-broker/src/proxy/network-client";
import type {
  ProxyAuthoritySnapshot,
  ProxyResult,
} from "../../packages/secret-broker/src/proxy/proxy-protocol";
import type { SecretBrokerStateStore } from "../../packages/secret-broker/src/state-store";
import type { ProxyAccountingStore } from "../../packages/secret-broker/src/proxy/accounting-store";

export type FakeResponse =
  | { readonly status: number; readonly body: string | Buffer }
  | { readonly throw: ProxyNetworkError };

export interface CanaryBrokerHarness {
  readonly rootDir: string;
  readonly databasePath: string;
  readonly accountingPath: string;
  readonly proxy: CredentialProxy;
  readonly requests: ProxyOutboundRequest[];
  readonly audits: CredentialProxyAuditEvent[];
  readonly store: SecretBrokerStateStore;
  readonly accounting: ProxyAccountingStore;
  enqueue(response: FakeResponse): void;
  /** Seal `token` through the real 8C at-rest path and return an active handle. */
  activeHandle(token: string, provider: string, expectationDigest: string): string;
  revoke(handleId: string): void;
  authority(input: {
    provider: string;
    handleId: string;
    expectationDigest: string;
  }): ProxyAuthoritySnapshot;
  /** Read the persisted broker files (DB + WAL + accounting) as raw bytes. */
  readPersistedBytes(): Buffer;
  cleanup(): void;
}

/**
 * A file-backed broker + Credential Proxy harness that seals a canary as real
 * material through the real 8C at-rest path. Unlike the in-memory unit harness
 * it persists to disk so the durable files can be scanned for plaintext leakage.
 */
export function createCanaryBrokerHarness(): CanaryBrokerHarness {
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "canary-broker-"));
  fs.chmodSync(rootDir, 0o700);
  const root = establishBrokerRoot({ rootDir });
  const databasePath = path.join(rootDir, "broker-state.db");
  const accountingPath = path.join(rootDir, "proxy-accounting.db");
  const store = openSecretBrokerStateStore({ databasePath });
  const accounting = openProxyAccountingStore({ databasePath: accountingPath });
  const requests: ProxyOutboundRequest[] = [];
  const audits: CredentialProxyAuditEvent[] = [];
  const responses: FakeResponse[] = [];
  const clock = { now: 1_700_000_000_000 };
  let counter = 0;

  const network: ProxyNetworkClient = {
    async send(request: ProxyOutboundRequest) {
      requests.push(request);
      const next = responses.shift();
      if (!next) throw new ProxyNetworkError("transport");
      if ("throw" in next) throw next.throw;
      const body = Buffer.isBuffer(next.body) ? next.body : Buffer.from(next.body, "utf8");
      return { status: next.status, body };
    },
  };

  const proxy = createCredentialProxy({
    store,
    accounting,
    network,
    clock: () => clock.now,
    resolveCredential: (brokerKind, storedMaterial) =>
      brokerKind === "oauth-envelope" ? openAtRest(storedMaterial, root.atRestKey) : null,
    audit: (event) => audits.push(event),
  });

  return {
    rootDir,
    databasePath,
    accountingPath,
    proxy,
    requests,
    audits,
    store,
    accounting,
    enqueue(response) {
      responses.push(response);
    },
    activeHandle(token, provider, expectationDigest) {
      counter += 1;
      const handleId = `hnd_canary_${counter}`;
      const receiptId = `rcp_canary_${counter}`;
      store.prepare({
        operationId: `op_canary_${counter}`,
        handleId,
        receiptId,
        provider,
        brokerKind: "oauth-envelope",
        usage: "installation",
        expectationDigest,
        replacesHandleId: null,
        issuedAtMs: clock.now,
        expiresAtMs: clock.now + 60_000,
        secretMaterial: sealAtRest(Buffer.from(token, "utf8"), root.atRestKey),
      });
      store.finalize(handleId, receiptId);
      return handleId;
    },
    revoke(handleId) {
      store.revoke(handleId);
    },
    authority(input) {
      return Object.freeze({
        provider: input.provider,
        handleId: input.handleId,
        handleGeneration: 1,
        expectationDigest: input.expectationDigest,
        installationId: "inst_canary",
        installationRevision: 1,
        bindingId: null,
        bindingRevision: null,
      });
    },
    readPersistedBytes(): Buffer {
      const chunks: Buffer[] = [];
      for (const base of [databasePath, accountingPath]) {
        for (const suffix of ["", "-wal", "-shm", "-journal"]) {
          try {
            chunks.push(fs.readFileSync(`${base}${suffix}`));
          } catch {
            // sidecar may not exist yet
          }
        }
      }
      return Buffer.concat(chunks);
    },
    cleanup() {
      store.close();
      accounting.close();
      fs.rmSync(rootDir, { recursive: true, force: true });
    },
  };
}

export type { ProxyResult };
