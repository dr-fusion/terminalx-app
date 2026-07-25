import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { establishBrokerRoot } from "../../../packages/secret-broker/src/broker-root";
import { openSecretBrokerStateStore } from "../../../packages/secret-broker/src/state-store";
import { openProxyAccountingStore } from "../../../packages/secret-broker/src/proxy/accounting-store";
import { openAtRest, sealAtRest } from "../../../packages/secret-broker/src/at-rest";
import {
  createCredentialProxy,
  type CredentialProxy,
  type CredentialProxyAuditEvent,
} from "../../../packages/secret-broker/src/proxy/credential-proxy";
import type {
  ProxyNetworkClient,
  ProxyOutboundRequest,
} from "../../../packages/secret-broker/src/proxy/network-client";
import { ProxyNetworkError } from "../../../packages/secret-broker/src/proxy/network-client";
import type { ProxyAuthoritySnapshot } from "../../../packages/secret-broker/src/proxy/proxy-protocol";

export type FakeResponse =
  | { readonly status: number; readonly body: string | Buffer }
  | { readonly throw: ProxyNetworkError };

export interface FakeNetworkClient extends ProxyNetworkClient {
  readonly requests: ProxyOutboundRequest[];
  enqueue(response: FakeResponse): void;
}

export function createFakeNetworkClient(): FakeNetworkClient {
  const requests: ProxyOutboundRequest[] = [];
  const responses: FakeResponse[] = [];
  return {
    requests,
    enqueue(response: FakeResponse): void {
      responses.push(response);
    },
    async send(request: ProxyOutboundRequest) {
      requests.push(request);
      const next = responses.shift();
      if (!next) throw new ProxyNetworkError("transport");
      if ("throw" in next) throw next.throw;
      const body = Buffer.isBuffer(next.body) ? next.body : Buffer.from(next.body, "utf8");
      return { status: next.status, body };
    },
  };
}

export interface ProxyHarness {
  readonly rootDir: string;
  readonly proxy: CredentialProxy;
  readonly network: FakeNetworkClient;
  readonly accounting: ReturnType<typeof openProxyAccountingStore>;
  readonly audits: CredentialProxyAuditEvent[];
  readonly clock: { now: number };
  /** Persist an active handle sealing `token`, and return its id/expectation. */
  activeHandle(input: {
    token: string;
    provider: string;
    expectationDigest: string;
    brokerKind?: "oauth-envelope" | "onepassword-connect";
    materialOverride?: Buffer;
  }): { handleId: string; expectationDigest: string };
  revoke(handleId: string): void;
  authority(input: {
    provider: string;
    handleId: string;
    expectationDigest: string;
    generation?: number;
    installationRevision?: number;
    bindingId?: string | null;
    bindingRevision?: number | null;
  }): ProxyAuthoritySnapshot;
  cleanup(): void;
}

export function createProxyHarness(): ProxyHarness {
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "credential-proxy-"));
  fs.chmodSync(rootDir, 0o700);
  const root = establishBrokerRoot({ rootDir });
  const store = openSecretBrokerStateStore({ databasePath: ":memory:" });
  const accounting = openProxyAccountingStore({ databasePath: ":memory:" });
  const network = createFakeNetworkClient();
  const audits: CredentialProxyAuditEvent[] = [];
  const clock = { now: 1_700_000_000_000 };
  let counter = 0;

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
    proxy,
    network,
    accounting,
    audits,
    clock,
    activeHandle(input) {
      counter += 1;
      const handleId = `hnd_test_${counter}`;
      const receiptId = `rcp_test_${counter}`;
      const brokerKind = input.brokerKind ?? "oauth-envelope";
      const material =
        input.materialOverride ?? sealAtRest(Buffer.from(input.token, "utf8"), root.atRestKey);
      store.prepare({
        operationId: `op_test_${counter}`,
        handleId,
        receiptId,
        provider: input.provider,
        brokerKind,
        usage: "installation",
        expectationDigest: input.expectationDigest,
        replacesHandleId: null,
        issuedAtMs: clock.now,
        expiresAtMs: clock.now + 60_000,
        secretMaterial: material,
      });
      store.finalize(handleId, receiptId);
      return { handleId, expectationDigest: input.expectationDigest };
    },
    revoke(handleId: string) {
      store.revoke(handleId);
    },
    authority(input) {
      return Object.freeze({
        provider: input.provider,
        handleId: input.handleId,
        handleGeneration: input.generation ?? 1,
        expectationDigest: input.expectationDigest,
        installationId: "inst_test",
        installationRevision: input.installationRevision ?? 1,
        bindingId: input.bindingId ?? null,
        bindingRevision: input.bindingRevision ?? null,
      });
    },
    cleanup() {
      store.close();
      accounting.close();
      fs.rmSync(rootDir, { recursive: true, force: true });
    },
  };
}

const HEX64 = "1".repeat(64);
export const TELEGRAM_EXPECTATION_DIGEST = "a".repeat(64);
export const SLACK_EXPECTATION_DIGEST = "b".repeat(64);
export { HEX64 };
