import { afterEach, describe, expect, it } from "vitest";
import {
  createProxyHarness,
  TELEGRAM_EXPECTATION_DIGEST,
  type ProxyHarness,
} from "./support/credential-proxy-harness";

let harness: ProxyHarness;
afterEach(() => harness?.cleanup());

let nonce = 0;
async function execute(
  h: ProxyHarness,
  authority: ReturnType<ProxyHarness["authority"]>,
  params: unknown = { chatId: "1", text: "x" }
) {
  nonce += 1;
  return h.proxy.execute({
    operationId: `op_fence_${nonce}`,
    operation: "telegram.sendMessage",
    authority,
    params,
  });
}

describe("Credential Proxy authority fences", () => {
  it("denies a revoked (rotated-away) handle and never attaches the credential", async () => {
    harness = createProxyHarness();
    const handle = harness.activeHandle({
      token: "12345:BOT",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    harness.revoke(handle.handleId);
    harness.network.enqueue({ status: 200, body: JSON.stringify({ ok: true, result: {} }) });

    const result = await execute(
      harness,
      harness.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      })
    );

    expect(result.resultClass).toBe("denied");
    expect(result.errorCode).toBe("handle-inactive");
    expect(harness.network.requests).toHaveLength(0);
    expect(harness.audits.at(-1)).toMatchObject({
      resultClass: "denied",
      errorCode: "handle-inactive",
    });
  });

  it("denies an unknown handle id (stale generation pointing at a rotated-away handle)", async () => {
    harness = createProxyHarness();
    const result = await execute(
      harness,
      harness.authority({
        provider: "telegram",
        handleId: "hnd_does_not_exist",
        expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
        generation: 7,
      })
    );
    expect(result.resultClass).toBe("denied");
    expect(result.errorCode).toBe("handle-inactive");
    expect(harness.network.requests).toHaveLength(0);
  });

  it("denies a mismatched authority digest (also the stale-installation-revision case)", async () => {
    harness = createProxyHarness();
    // The handle is bound to the authority digest for one exact registration.
    const handle = harness.activeHandle({
      token: "12345:BOT",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    // A caller presenting a digest computed against a different installation
    // revision / authority target resolves to a different digest and is denied.
    const staleDigest = "c".repeat(64);
    const result = await execute(
      harness,
      harness.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: staleDigest,
        installationRevision: 2,
      })
    );
    expect(result.resultClass).toBe("denied");
    expect(result.errorCode).toBe("authority-mismatch");
    expect(harness.network.requests).toHaveLength(0);
    expect(harness.audits.at(-1)).toMatchObject({
      resultClass: "denied",
      errorCode: "authority-mismatch",
    });
  });

  it("denies a broker kind that holds no broker-local usable credential", async () => {
    harness = createProxyHarness();
    // A onepassword-connect handle stores only an external reference, which the
    // 8D proxy cannot resolve for use; it must fail closed.
    const handle = harness.activeHandle({
      token: "unused",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
      brokerKind: "onepassword-connect",
      materialOverride: Buffer.from(JSON.stringify({ schema: 1, vaultId: "v", itemId: "i" })),
    });
    const result = await execute(
      harness,
      harness.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      })
    );
    expect(result.resultClass).toBe("denied");
    expect(result.errorCode).toBe("unsupported-credential-kind");
    expect(harness.network.requests).toHaveLength(0);
  });

  it("audits every denied call with a digest-only authority snapshot", async () => {
    harness = createProxyHarness();
    await execute(
      harness,
      harness.authority({
        provider: "telegram",
        handleId: "hnd_missing",
        expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
      })
    );
    const audit = harness.audits.at(-1)!;
    expect(audit.authoritySnapshotDigest).toMatch(/^[0-9a-f]{64}$/);
    // The audit carries no handle id or raw identifiers, only a digest.
    expect(JSON.stringify(audit)).not.toContain("hnd_missing");
  });
});
