import { createHash } from "node:crypto";
import { canonicalRuntimeJson } from "../runtime/runtime-command-canonical";

/**
 * Phase 11A — per-scope hash chains for the append-only attention logs.
 *
 * The escalation log (chained per Session) and the delivery log (chained per
 * User) carry the same tamper-evident discipline as the Session Event Chain:
 * each row commits to its immutable content and to the hash of its predecessor
 * in the same scope, from a fixed, domain-separated genesis root. A reader can
 * recompute either chain and detect any tamper, gap, reorder, or deletion.
 *
 * These are DISTINCT domains from the Session Event Chain so an attention log
 * hash can never be confused with a session-event hash, and DISTINCT from each
 * other so an escalation row can never masquerade as a delivery row.
 */

export const ATTENTION_CHAIN_SCHEMA = 1 as const;

const ESCALATION_GENESIS_DOMAIN = "terminalx/attention/escalation-chain/genesis/v1\0";
const ESCALATION_DIGEST_DOMAIN = "terminalx/attention/escalation-chain/entry/v1\0";
const DELIVERY_GENESIS_DOMAIN = "terminalx/attention/delivery-chain/genesis/v1\0";
const DELIVERY_DIGEST_DOMAIN = "terminalx/attention/delivery-chain/entry/v1\0";

const SHA256 = /^[0-9a-f]{64}$/;

export const ATTENTION_ESCALATION_GENESIS: string = createHash("sha256")
  .update(ESCALATION_GENESIS_DOMAIN, "utf8")
  .digest("hex");

export const ATTENTION_DELIVERY_GENESIS: string = createHash("sha256")
  .update(DELIVERY_GENESIS_DOMAIN, "utf8")
  .digest("hex");

export class AttentionChainError extends Error {
  constructor(readonly code: "missing-prior-hash") {
    super("Attention chain input is invalid");
    this.name = "AttentionChainError";
  }
}

function previousHash(sequence: number, priorHash: string | null, genesis: string): string {
  if (sequence === 1) return genesis;
  if (priorHash === null || !SHA256.test(priorHash)) {
    throw new AttentionChainError("missing-prior-hash");
  }
  return priorHash;
}

export interface EscalationChainContent {
  readonly sessionId: string;
  readonly sequence: number;
  readonly itemKind: string;
  readonly itemSequence: number;
  readonly responsibleUserId: string;
  readonly supervisorUserId: string;
  readonly deadlineAtMs: number;
  readonly escalatedAtMs: number;
}

export interface DeliveryChainContent {
  readonly userId: string;
  readonly sequence: number;
  readonly sessionId: string;
  readonly itemKind: string;
  readonly itemSequence: number;
  readonly bindingId: string;
  readonly outcome: string;
}

export function chainedEscalationHashes(
  priorHash: string | null,
  content: EscalationChainContent
): { readonly prevHash: string; readonly hash: string } {
  const prevHash = previousHash(content.sequence, priorHash, ATTENTION_ESCALATION_GENESIS);
  const hash = createHash("sha256")
    .update(ESCALATION_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson({ schema: ATTENTION_CHAIN_SCHEMA, ...content, prevHash }), "utf8")
    .digest("hex");
  return { prevHash, hash };
}

export function chainedDeliveryHashes(
  priorHash: string | null,
  content: DeliveryChainContent
): { readonly prevHash: string; readonly hash: string } {
  const prevHash = previousHash(content.sequence, priorHash, ATTENTION_DELIVERY_GENESIS);
  const hash = createHash("sha256")
    .update(DELIVERY_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson({ schema: ATTENTION_CHAIN_SCHEMA, ...content, prevHash }), "utf8")
    .digest("hex");
  return { prevHash, hash };
}
