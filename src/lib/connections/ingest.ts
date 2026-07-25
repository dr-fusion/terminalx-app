import type { ConnectionProvider, InboundAttributionResolution } from "./contracts";
import type { WebhookDeliveryDedup } from "./webhook-dedup";
import type { NormalizedInboundMessage } from "./providers/types";

/**
 * Inbound ingestion pipeline (Slice 8E, decision 5). Turns a verified, normalized
 * provider message into a Team Session command with exact attribution, or routes
 * it through the separate fail-closed anonymous path. Every outcome is durable and
 * idempotent:
 *
 * - Replayed deliveries are acknowledged-but-dropped (dedup), never re-processed.
 * - A linked-identity comment/directive is appended through the kernel command
 *   surface with an idempotency key derived from the provider replay id, so a
 *   crash between processing and marking never produces a second Session event.
 * - Anonymous ingress (no linked identity) is fail-closed: it never yields a
 *   directive and never mutates the Session; it is acknowledged and audited only
 *   when the Binding policy explicitly permits unlinked inbound, and rejected
 *   (audited) otherwise.
 */

export interface InboundKernelComment {
  readonly type: "comment.add";
  readonly sessionId: string;
  readonly body: string;
  readonly actorUserId: string;
  readonly idempotencyScope: string;
  readonly idempotencyKey: string;
}

export interface InboundKernelDirective {
  readonly type: "directive.enqueue";
  readonly sessionId: string;
  readonly body: string;
  readonly actorUserId: string;
  readonly expectedSteeringRevision: number;
  readonly idempotencyScope: string;
  readonly idempotencyKey: string;
}

export type InboundKernelCommand = InboundKernelComment | InboundKernelDirective;

export interface InboundDispatchResult {
  readonly accepted: boolean;
  readonly replayed: boolean;
}

export type InboundAuditReason =
  | "dropped-replay"
  | "processed-comment"
  | "processed-directive"
  | "anonymous-acknowledged"
  | "rejected-unlinked-identity"
  | "rejected-directive-requires-linked-identity"
  | "rejected-no-active-binding"
  | "rejected-dispatch-denied";

export interface InboundAuditEvent {
  readonly provider: ConnectionProvider;
  readonly installationId: string;
  readonly bindingId: string;
  readonly reason: InboundAuditReason;
  readonly replayId: string;
}

export type InboundOutcome =
  | { readonly kind: "dropped-replay" }
  | {
      readonly kind: "processed";
      readonly action: "comment" | "directive";
      readonly replayed: boolean;
    }
  | { readonly kind: "anonymous-acknowledged" }
  | { readonly kind: "rejected"; readonly reason: InboundAuditReason };

export interface IngestInboundInput {
  readonly message: NormalizedInboundMessage;
  /** The resolved candidate Channel Binding for this conversation. */
  readonly bindingId: string;
  readonly expectedBindingRevision: number;
  readonly expectedInstallationRevision: number;
  readonly installationId: string;
  /** Requested action; a directive additionally requires a linked identity + steerer authority. */
  readonly action: "comment" | "directive";
  /** Required only when `action` is "directive". */
  readonly expectedSteeringRevision?: number;
}

export interface IngestInboundDeps {
  readonly dedup: WebhookDeliveryDedup;
  readonly resolveInboundAttribution: (input: {
    action: "comment" | "directive";
    provider: ConnectionProvider;
    installationId: string;
    expectedInstallationRevision: number;
    bindingId: string;
    expectedBindingRevision: number;
    externalTenantId: string;
    externalSubject: string;
    conversationKind: "channel" | "thread" | "topic";
    externalConversationId: string;
    externalThreadId?: string;
  }) => InboundAttributionResolution | null;
  /** Look up the active Binding inbound policy for the anonymous fail-closed path. */
  readonly bindingInboundPolicy: (bindingId: string) => {
    mode: "comments-only" | "comments-and-directives" | "notifications-only";
    requireLinkedIdentity: boolean;
  } | null;
  readonly dispatch: (command: InboundKernelCommand) => Promise<InboundDispatchResult>;
  readonly clock?: () => number;
  readonly audit?: (event: InboundAuditEvent) => void;
}

export async function ingestInboundMessage(
  deps: IngestInboundDeps,
  input: IngestInboundInput
): Promise<InboundOutcome> {
  const now = (deps.clock ?? Date.now)();
  const { message } = input;

  const emit = (reason: InboundAuditReason): void =>
    deps.audit?.({
      provider: message.provider,
      installationId: input.installationId,
      bindingId: input.bindingId,
      reason,
      replayId: message.replayId,
    });

  // 1) Durable replay dedup: an already-seen delivery is acknowledged-but-dropped.
  if (
    deps.dedup.hasDelivery({
      installationId: input.installationId,
      provider: message.provider,
      replayId: message.replayId,
    })
  ) {
    emit("dropped-replay");
    return { kind: "dropped-replay" };
  }

  const recordDelivery = (): void => {
    deps.dedup.recordDelivery({
      installationId: input.installationId,
      provider: message.provider,
      replayId: message.replayId,
      ...(message.provider === "telegram" && /^[0-9]+$/.test(message.replayId)
        ? { monotonicOrdinal: Number(message.replayId) }
        : {}),
      receivedAtMs: now,
    });
  };

  // 2) Linked-identity attribution through the authority.
  const resolution = deps.resolveInboundAttribution({
    action: input.action,
    provider: message.provider,
    installationId: input.installationId,
    expectedInstallationRevision: input.expectedInstallationRevision,
    bindingId: input.bindingId,
    expectedBindingRevision: input.expectedBindingRevision,
    externalTenantId: message.externalTenantId,
    externalSubject: message.externalSubject,
    conversationKind: message.conversationKind,
    externalConversationId: message.externalConversationId,
    ...(message.externalThreadId.length > 0 ? { externalThreadId: message.externalThreadId } : {}),
  });

  if (resolution) {
    const idempotencyScope = `${message.provider}:${message.externalTenantId}`;
    const command: InboundKernelCommand =
      input.action === "directive"
        ? {
            type: "directive.enqueue",
            sessionId: resolution.session.id,
            body: message.text,
            actorUserId: resolution.identity.userId,
            expectedSteeringRevision:
              input.expectedSteeringRevision ?? resolution.session.steeringRevision,
            idempotencyScope,
            idempotencyKey: message.replayId,
          }
        : {
            type: "comment.add",
            sessionId: resolution.session.id,
            body: message.text,
            actorUserId: resolution.identity.userId,
            idempotencyScope,
            idempotencyKey: message.replayId,
          };
    let result: InboundDispatchResult;
    try {
      result = await deps.dispatch(command);
    } catch {
      // A steering-authority / stale-revision denial is audited and acknowledged
      // without processing; the delivery is recorded so it is not retried blindly.
      recordDelivery();
      emit("rejected-dispatch-denied");
      return { kind: "rejected", reason: "rejected-dispatch-denied" };
    }
    recordDelivery();
    const auditReason = input.action === "directive" ? "processed-directive" : "processed-comment";
    emit(auditReason);
    return { kind: "processed", action: input.action, replayed: result.replayed };
  }

  // 3) No linked identity: the separate fail-closed anonymous ingress path.
  // A directive can never resolve anonymously.
  if (input.action === "directive") {
    recordDelivery();
    emit("rejected-directive-requires-linked-identity");
    return { kind: "rejected", reason: "rejected-directive-requires-linked-identity" };
  }
  const policy = deps.bindingInboundPolicy(input.bindingId);
  if (!policy) {
    recordDelivery();
    emit("rejected-no-active-binding");
    return { kind: "rejected", reason: "rejected-no-active-binding" };
  }
  if (policy.requireLinkedIdentity) {
    // Fail closed: the Binding demands a linked identity and none resolved.
    recordDelivery();
    emit("rejected-unlinked-identity");
    return { kind: "rejected", reason: "rejected-unlinked-identity" };
  }
  // Anonymous inbound is acknowledged and audited but never mutates the Session
  // and never becomes a directive.
  recordDelivery();
  emit("anonymous-acknowledged");
  return { kind: "anonymous-acknowledged" };
}
