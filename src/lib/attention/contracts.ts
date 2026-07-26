/**
 * Phase 11A — public contracts for the global attention inbox.
 *
 * An {@link AttentionItem} is one attention/steering ask directed at a single
 * User (a mention, a Handoff offer awaiting their acceptance, or an
 * assignee-required ask a Supervisor must resolve), projected across every Team
 * Session the User can currently see. The inbox never crosses a
 * session-visibility boundary: every source is fenced to a currently active
 * Participant.
 */

export type AttentionItemKind = "mention" | "handoff-offer" | "assignee-required";

export interface AttentionItem {
  /** Stable, deterministic identity for read/ack: `kind:sessionId:itemSequence`. */
  readonly itemId: string;
  readonly kind: AttentionItemKind;
  readonly sessionId: string;
  readonly teamId: string;
  readonly projectId: string;
  readonly sessionName: string;
  readonly sessionStatus: "active" | "awaiting_assignee" | "ended";
  /** The originating Session Event sequence; the stable ordering key within a Session. */
  readonly itemSequence: number;
  readonly createdAtMs: number;
  /** Present only for items that carry a deadline (Handoff offers). */
  readonly deadlineAtMs: number | null;
  readonly read: boolean;
  /** Whether this item has already been escalated to a Supervisor. */
  readonly escalated: boolean;
  /** The User who created the ask (mention author, Handoff offerer), when attributable. */
  readonly actorUserId: string | null;
  readonly summary: string;
}

export interface AttentionInboxPage {
  readonly items: readonly AttentionItem[];
  readonly unreadCount: number;
  readonly nextCursor: string | null;
}

export interface AttentionInboxQuery {
  readonly userId: string;
  readonly teamId?: string;
  readonly limit?: number;
  readonly cursor?: string | null;
  readonly unreadOnly?: boolean;
}

export interface AttentionEscalation {
  readonly id: string;
  readonly sessionId: string;
  readonly sequence: number;
  readonly itemKind: "handoff-offer" | "assignee-required";
  readonly itemSequence: number;
  readonly responsibleUserId: string;
  readonly supervisorUserId: string;
  readonly deadlineAtMs: number;
  readonly escalatedAtMs: number;
}

export type AttentionDeliveryOutcome =
  | "delivered"
  | "not-routed"
  | "denied"
  | "retries-exhausted"
  | "retry-scheduled"
  | "no-binding"
  | "already-delivered";

export interface AttentionDeliveryResult {
  readonly userId: string;
  readonly sessionId: string;
  readonly itemKind: AttentionItem["kind"] | "escalation";
  readonly itemSequence: number;
  readonly outcome: AttentionDeliveryOutcome;
}

/** A resolved outbound Binding for one Session, or null when none is authorized. */
export interface SessionOutboundBindingRef {
  readonly bindingId: string;
  readonly expectedBindingRevision: number;
  readonly expectedInstallationRevision: number;
}

export interface AttentionOutboundDecision {
  readonly delivered: boolean;
  readonly shouldRetry: boolean;
  readonly reason: "delivered" | "not-routed" | "retry-scheduled" | "retries-exhausted" | "denied";
}

/**
 * Injected dependencies for notification delivery. Both seams route through the
 * EXISTING connection egress (`deliverOutboundMessage` and the Binding
 * authority) so the attention subsystem never builds a second egress path and
 * fails closed when no Binding/authority exists.
 */
export interface AttentionDeliveryDeps {
  readonly resolveSessionBinding: (sessionId: string) => SessionOutboundBindingRef | null;
  readonly deliverOutbound: (input: {
    readonly bindingId: string;
    readonly expectedBindingRevision: number;
    readonly expectedInstallationRevision: number;
    readonly messageKind: "mention" | "session-message";
    readonly includesArtifacts: boolean;
    readonly text: string;
    readonly attempt: number;
  }) => Promise<AttentionOutboundDecision>;
}

export const MAX_ATTENTION_PAGE = 100;
export const DEFAULT_ATTENTION_PAGE = 30;
export const MAX_ATTENTION_SCAN = 1000;
