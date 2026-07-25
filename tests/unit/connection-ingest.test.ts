import { describe, expect, it, vi } from "vitest";
import {
  ingestInboundMessage,
  type IngestInboundDeps,
  type InboundKernelCommand,
} from "@/lib/connections/ingest";
import type { WebhookDeliveryDedup } from "@/lib/connections/webhook-dedup";
import type { InboundAttributionResolution } from "@/lib/connections/contracts";
import type { NormalizedInboundMessage } from "@/lib/connections/providers/types";

function fakeDedup(): WebhookDeliveryDedup {
  const seen = new Set<string>();
  const key = (i: { installationId: string; provider: string; replayId: string }) =>
    `${i.installationId}\0${i.provider}\0${i.replayId}`;
  return {
    hasDelivery: (i) => seen.has(key(i)),
    recordDelivery: (i) => {
      const k = key(i);
      if (seen.has(k)) return { recorded: false };
      seen.add(k);
      return { recorded: true };
    },
    latestOrdinal: () => null,
  };
}

function message(overrides: Partial<NormalizedInboundMessage> = {}): NormalizedInboundMessage {
  return Object.freeze({
    provider: "telegram",
    externalTenantId: "998877",
    externalSubject: "555",
    conversationKind: "channel",
    externalConversationId: "-100",
    externalThreadId: "",
    text: "hello team",
    replayId: "42",
    isMention: false,
    ...overrides,
  });
}

function resolution(): InboundAttributionResolution {
  return Object.freeze({
    direction: "inbound",
    action: "comment",
    provider: "telegram",
    session: Object.freeze({
      id: "session-1",
      teamId: "team-1",
      accessRevision: 1,
      steeringRevision: 4,
      controlRevision: 1,
      runtimeAuthorizationGeneration: 1,
    }),
    installation: Object.freeze({
      id: "inst-1",
      revision: 1,
      externalTenantId: "998877",
      externalAppId: "998877",
      credentialHandleId: "txch_v1_" + "0".repeat(64),
      credentialHandleGeneration: 1,
    }),
    binding: Object.freeze({
      id: "binding-1",
      revision: 2,
      conversationKind: "channel",
      externalConversationId: "-100",
      externalThreadId: "",
      inboundPolicy: Object.freeze({ mode: "comments-only", requireLinkedIdentity: true }),
      inboundPolicyDigest: "d".repeat(64),
    }),
    identity: Object.freeze({
      connectionId: "conn-1",
      connectionGeneration: 1,
      userId: "user-9",
      externalSubject: "555",
      scopes: ["identity:telegram"],
      scopesDigest: "e".repeat(64),
      credentialHandleId: null,
      credentialHandleGeneration: null,
    }),
  });
}

function baseInput() {
  return {
    message: message(),
    bindingId: "binding-1",
    expectedBindingRevision: 2,
    expectedInstallationRevision: 1,
    installationId: "inst-1",
    action: "comment" as const,
  };
}

describe("inbound ingestion pipeline", () => {
  it("appends a linked-identity comment with exact attribution and idempotency", async () => {
    const dispatched: InboundKernelCommand[] = [];
    const deps: IngestInboundDeps = {
      dedup: fakeDedup(),
      resolveInboundAttribution: () => resolution(),
      bindingInboundPolicy: () => ({ mode: "comments-only", requireLinkedIdentity: true }),
      dispatch: async (command) => {
        dispatched.push(command);
        return { accepted: true, replayed: false };
      },
    };
    const outcome = await ingestInboundMessage(deps, baseInput());
    expect(outcome).toEqual({ kind: "processed", action: "comment", replayed: false });
    expect(dispatched[0]).toMatchObject({
      type: "comment.add",
      sessionId: "session-1",
      body: "hello team",
      actorUserId: "user-9",
      idempotencyScope: "telegram:998877",
      idempotencyKey: "42",
    });
  });

  it("acknowledges-but-drops a replayed delivery without re-dispatching", async () => {
    const dedup = fakeDedup();
    const dispatch = vi.fn(async () => ({ accepted: true, replayed: false }));
    const deps: IngestInboundDeps = {
      dedup,
      resolveInboundAttribution: () => resolution(),
      bindingInboundPolicy: () => ({ mode: "comments-only", requireLinkedIdentity: true }),
      dispatch,
    };
    await ingestInboundMessage(deps, baseInput());
    const second = await ingestInboundMessage(deps, baseInput());
    expect(second).toEqual({ kind: "dropped-replay" });
    expect(dispatch).toHaveBeenCalledOnce();
  });

  it("never double-processes across a crash between process and mark (kernel idempotency)", async () => {
    // Simulate: first attempt dispatches but the delivery mark is 'lost' (a fresh
    // dedup on retry). The kernel replays idempotently, producing no second event.
    const dispatch = vi.fn(async () => ({ accepted: true, replayed: true }));
    const deps = (dedup: WebhookDeliveryDedup): IngestInboundDeps => ({
      dedup,
      resolveInboundAttribution: () => resolution(),
      bindingInboundPolicy: () => ({ mode: "comments-only", requireLinkedIdentity: true }),
      dispatch,
    });
    await ingestInboundMessage(deps(fakeDedup()), baseInput());
    const retry = await ingestInboundMessage(deps(fakeDedup()), baseInput());
    expect(retry).toEqual({ kind: "processed", action: "comment", replayed: true });
  });

  it("acknowledges anonymous inbound only when the Binding permits unlinked identity", async () => {
    const deps: IngestInboundDeps = {
      dedup: fakeDedup(),
      resolveInboundAttribution: () => null,
      bindingInboundPolicy: () => ({ mode: "notifications-only", requireLinkedIdentity: false }),
      dispatch: async () => {
        throw new Error("anonymous ingress must not dispatch a Session command");
      },
    };
    expect(await ingestInboundMessage(deps, baseInput())).toEqual({
      kind: "anonymous-acknowledged",
    });
  });

  it("fails closed when no linked identity resolves and the Binding requires one", async () => {
    const deps: IngestInboundDeps = {
      dedup: fakeDedup(),
      resolveInboundAttribution: () => null,
      bindingInboundPolicy: () => ({ mode: "comments-only", requireLinkedIdentity: true }),
      dispatch: async () => ({ accepted: true, replayed: false }),
    };
    expect(await ingestInboundMessage(deps, baseInput())).toEqual({
      kind: "rejected",
      reason: "rejected-unlinked-identity",
    });
  });

  it("never yields a directive from the anonymous path", async () => {
    const deps: IngestInboundDeps = {
      dedup: fakeDedup(),
      resolveInboundAttribution: () => null,
      bindingInboundPolicy: () => ({
        mode: "comments-and-directives",
        requireLinkedIdentity: false,
      }),
      dispatch: async () => {
        throw new Error("must not dispatch");
      },
    };
    expect(await ingestInboundMessage(deps, { ...baseInput(), action: "directive" })).toEqual({
      kind: "rejected",
      reason: "rejected-directive-requires-linked-identity",
    });
  });

  it("enqueues a linked directive with the resolved steering revision", async () => {
    const dispatched: InboundKernelCommand[] = [];
    const directiveResolution = { ...resolution(), action: "directive" as const };
    const deps: IngestInboundDeps = {
      dedup: fakeDedup(),
      resolveInboundAttribution: () => directiveResolution,
      bindingInboundPolicy: () => ({
        mode: "comments-and-directives",
        requireLinkedIdentity: true,
      }),
      dispatch: async (command) => {
        dispatched.push(command);
        return { accepted: true, replayed: false };
      },
    };
    const outcome = await ingestInboundMessage(deps, { ...baseInput(), action: "directive" });
    expect(outcome).toEqual({ kind: "processed", action: "directive", replayed: false });
    expect(dispatched[0]).toMatchObject({
      type: "directive.enqueue",
      expectedSteeringRevision: 4,
      actorUserId: "user-9",
    });
  });

  it("audits and acknowledges a dispatch denial without processing", async () => {
    const deps: IngestInboundDeps = {
      dedup: fakeDedup(),
      resolveInboundAttribution: () => ({ ...resolution(), action: "directive" }),
      bindingInboundPolicy: () => ({
        mode: "comments-and-directives",
        requireLinkedIdentity: true,
      }),
      dispatch: async () => {
        throw new Error("stale-revision");
      },
    };
    expect(await ingestInboundMessage(deps, { ...baseInput(), action: "directive" })).toEqual({
      kind: "rejected",
      reason: "rejected-dispatch-denied",
    });
  });
});
