import type Database from "better-sqlite3";
import {
  withConnectionAuthority as defaultWithConnectionAuthority,
  withConnectionDatabase as defaultWithConnectionDatabase,
} from "../identity-service";
import { configuredSecretBrokerRoot } from "./secret-broker-composition";
import {
  createProviderExchangeClient,
  type ProviderExchangeClient,
} from "./provider-exchange-client";
import type { ConnectionAuthority } from "./authority";
import { createWebhookDeliveryDedup } from "./webhook-dedup";
import { createWebhookAuthStore } from "./webhook-auth";
import {
  findActiveBindingForConversation,
  findActiveInstallationById,
  findActiveSlackInstallationByTenant,
  installationCredentialExpectationDigest,
  listActiveSlackInstallations,
  type InstallationSnapshot,
} from "./read-model";
import {
  normalizeTelegramUpdate,
  verifyTelegramWebhookSecretToken,
} from "./providers/telegram-adapter";
import { normalizeSlackEvent } from "./providers/slack-adapter";
import {
  ingestInboundMessage,
  type InboundDispatchResult,
  type InboundKernelCommand,
} from "./ingest";
import type { NormalizedInboundMessage } from "./providers/types";
import { join } from "node:path";

/**
 * Provider webhook ingress (Slice 8E follow-up). These are UNAUTHENTICATED
 * public surfaces: no cookies, no request actors — every input is hostile until
 * the provider-authentication check passes (Telegram: per-installation secret
 * token verified by constant-time digest comparison against v15 state; Slack:
 * the v0 HMAC computed inside the broker with the stored signing secret plus the
 * ±300s replay window). Everything downstream is the exact 8E pipeline: replay
 * dedup → linked attribution or fail-closed anonymous path → idempotent kernel
 * command. Rejections are audited and acknowledged without processing; bounded
 * body sizes fail closed with 413.
 */
export type WebhookAuditReason =
  | "unauthorized"
  | "malformed"
  | "link-completed"
  | "link-rejected"
  | "no-binding"
  | "ingested"
  | "ingest-rejected"
  | "url-verification";

export interface WebhookAuditEvent {
  readonly provider: "telegram" | "slack";
  readonly installationId: string | null;
  readonly reason: WebhookAuditReason;
}

export interface WebhookHttpDependencies {
  withConnectionAuthority?: <T>(operation: (authority: ConnectionAuthority) => T) => T;
  withConnectionDatabase?: <T>(operation: (db: Database.Database) => T) => T;
  exchangeClient?: ProviderExchangeClient | null;
  /** Kernel dispatch adapter; production maps to the registered Team Sessions kernel. */
  dispatchKernelCommand?: (command: InboundKernelCommand) => Promise<InboundDispatchResult>;
  clock?: () => number;
  audit?: (event: WebhookAuditEvent) => void;
  maxBodyBytes?: number;
}

const DEFAULT_MAX_BODY_BYTES = 256 * 1024;

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

function unauthorized(): Response {
  return jsonResponse({ error: { code: "unauthorized" } }, 401);
}

function acknowledge(): Response {
  return jsonResponse({ ok: true });
}

function resolveDefaultExchangeClient(): ProviderExchangeClient | null {
  const rootDir = configuredSecretBrokerRoot();
  if (!rootDir) return null;
  return createProviderExchangeClient({ socketPath: join(rootDir, "broker.sock") });
}

async function readBoundedBody(request: Request, maxBytes: number): Promise<string | null> {
  const raw = await request.text();
  if (Buffer.byteLength(raw, "utf8") > maxBytes) return null;
  return raw;
}

function parseJsonObject(raw: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function requireKernelDispatch(
  deps: WebhookHttpDependencies
): (command: InboundKernelCommand) => Promise<InboundDispatchResult> {
  if (deps.dispatchKernelCommand) return deps.dispatchKernelCommand;
  return async () => {
    // Without a registered kernel the delivery is acknowledged-not-processed;
    // ingestInboundMessage records + audits the rejection.
    throw new Error("Team Session kernel is unavailable");
  };
}

async function ingestConversationMessage(
  deps: WebhookHttpDependencies,
  installation: InstallationSnapshot,
  message: NormalizedInboundMessage
): Promise<WebhookAuditReason> {
  const withDb = deps.withConnectionDatabase ?? defaultWithConnectionDatabase;
  const withAuthority = deps.withConnectionAuthority ?? defaultWithConnectionAuthority;
  const binding = withDb((db) =>
    findActiveBindingForConversation(db, {
      installationId: installation.id,
      conversationKind: message.conversationKind,
      externalConversationId: message.externalConversationId,
      externalThreadId: message.externalThreadId,
    })
  );
  if (!binding) return "no-binding";
  const outcome = await withDb((db) =>
    ingestInboundMessage(
      {
        dedup: createWebhookDeliveryDedup(db),
        resolveInboundAttribution: (input) =>
          withAuthority((authority) => authority.resolveInboundAttribution(input)),
        bindingInboundPolicy: () => binding.inboundPolicy,
        dispatch: requireKernelDispatch(deps),
        ...(deps.clock ? { clock: deps.clock } : {}),
      },
      {
        // The binding may route the exact thread or fall back to the channel
        // binding; attribution resolves against the binding's own conversation.
        message: Object.freeze({
          ...message,
          conversationKind: binding.conversationKind,
          externalConversationId: binding.externalConversationId,
          externalThreadId: binding.externalThreadId,
        }),
        bindingId: binding.id,
        expectedBindingRevision: binding.revision,
        expectedInstallationRevision: installation.revision,
        installationId: installation.id,
        action: "comment",
      }
    )
  );
  if (outcome.kind === "processed" || outcome.kind === "dropped-replay") return "ingested";
  if (outcome.kind === "anonymous-acknowledged") return "ingested";
  return "ingest-rejected";
}

/**
 * POST /api/connections/webhooks/telegram/[installationId]
 *
 * Authenticated by the per-installation `X-Telegram-Bot-Api-Secret-Token`
 * header, compared in constant time against the stored digest (v15). The raw
 * secret token never exists in main-process state.
 */
export async function handleTelegramWebhook(
  request: Request,
  installationId: string,
  deps: WebhookHttpDependencies = {}
): Promise<Response> {
  const audit = deps.audit ?? (() => undefined);
  const withDb = deps.withConnectionDatabase ?? defaultWithConnectionDatabase;
  const withAuthority = deps.withConnectionAuthority ?? defaultWithConnectionAuthority;
  if (
    typeof installationId !== "string" ||
    installationId.length < 1 ||
    installationId.length > 300
  ) {
    audit({ provider: "telegram", installationId: null, reason: "unauthorized" });
    return unauthorized();
  }
  let installation: InstallationSnapshot | null = null;
  let storedDigest: string | null = null;
  try {
    installation = withDb((db) => findActiveInstallationById(db, installationId, "telegram"));
    storedDigest = installation
      ? withDb((db) =>
          createWebhookAuthStore(db).latestWebhookAuthDigest(installationId, "telegram")
        )
      : null;
  } catch {
    installation = null;
  }
  const header = request.headers.get("x-telegram-bot-api-secret-token");
  // A missing installation, missing digest, or mismatched header are all the
  // same closed 401: this surface never discloses installation existence.
  if (!installation || !storedDigest || !verifyTelegramWebhookSecretToken(header, storedDigest)) {
    audit({ provider: "telegram", installationId, reason: "unauthorized" });
    return unauthorized();
  }
  const raw = await readBoundedBody(request, deps.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES);
  if (raw === null) return jsonResponse({ error: { code: "body-too-large" } }, 413);
  const update = parseJsonObject(raw);
  if (!update) {
    audit({ provider: "telegram", installationId, reason: "malformed" });
    return jsonResponse({ error: { code: "invalid-json" } }, 400);
  }

  const normalized = normalizeTelegramUpdate(update, {
    externalTenantId: installation.externalTenantId,
    externalAppId: installation.externalAppId,
  });

  if (normalized.deepLink) {
    // Linking: the verified deep link is the provider proof. Failures (expired,
    // replayed, tampered) are acknowledged-not-processed and audited; Telegram
    // must not retry a linking attempt.
    try {
      withAuthority((authority) =>
        authority.completeLinkChallenge({
          challenge: normalized.deepLink!.challenge,
          providerProof: normalized.deepLink,
        })
      );
      audit({ provider: "telegram", installationId, reason: "link-completed" });
    } catch {
      audit({ provider: "telegram", installationId, reason: "link-rejected" });
    }
    return acknowledge();
  }

  if (normalized.message) {
    const reason = await ingestConversationMessage(deps, installation, normalized.message);
    audit({ provider: "telegram", installationId, reason });
    return acknowledge();
  }

  // Non-message updates (edits, joins, …) are acknowledged and ignored.
  audit({ provider: "telegram", installationId, reason: "malformed" });
  return acknowledge();
}

async function verifySlackSignature(
  deps: WebhookHttpDependencies,
  installation: InstallationSnapshot,
  rawBody: string,
  timestampHeader: string | null,
  signatureHeader: string | null
): Promise<boolean> {
  const client =
    deps.exchangeClient === undefined ? resolveDefaultExchangeClient() : deps.exchangeClient;
  if (!client) return false;
  const timestamp = Number(timestampHeader);
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) return false;
  if (typeof signatureHeader !== "string" || signatureHeader.length < 1) return false;
  try {
    const result = await client.verifySlackWebhook({
      expectationDigest: installationCredentialExpectationDigest(installation),
      timestamp,
      body: rawBody,
      signature: signatureHeader,
    });
    return result.valid && result.withinReplayWindow;
  } catch {
    return false;
  }
}

/**
 * POST /api/connections/webhooks/slack
 *
 * Authenticated by the Slack v0 signature, computed inside the broker with the
 * installation's stored signing secret, plus the ±300s replay window. The
 * installation is resolved from the signed payload's team/app identity; a
 * payload whose signature does not verify against that installation's stored
 * secret is rejected without processing.
 */
export async function handleSlackWebhook(
  request: Request,
  deps: WebhookHttpDependencies = {}
): Promise<Response> {
  const audit = deps.audit ?? (() => undefined);
  const withDb = deps.withConnectionDatabase ?? defaultWithConnectionDatabase;
  const raw = await readBoundedBody(request, deps.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES);
  if (raw === null) return jsonResponse({ error: { code: "body-too-large" } }, 413);
  const envelope = parseJsonObject(raw);
  if (!envelope) {
    audit({ provider: "slack", installationId: null, reason: "malformed" });
    return jsonResponse({ error: { code: "invalid-json" } }, 400);
  }
  const timestampHeader = request.headers.get("x-slack-request-timestamp");
  const signatureHeader = request.headers.get("x-slack-signature");

  const normalized = normalizeSlackEvent(envelope);

  if (normalized.urlVerificationChallenge !== null) {
    // url_verification carries no team identity; verify the signature against
    // each active Slack installation's stored signing secret (bounded set).
    const installations = withDb((db) => listActiveSlackInstallations(db));
    for (const installation of installations) {
      if (await verifySlackSignature(deps, installation, raw, timestampHeader, signatureHeader)) {
        audit({ provider: "slack", installationId: installation.id, reason: "url-verification" });
        return jsonResponse({ challenge: normalized.urlVerificationChallenge });
      }
    }
    audit({ provider: "slack", installationId: null, reason: "unauthorized" });
    return unauthorized();
  }

  const teamId = typeof envelope.team_id === "string" ? envelope.team_id : null;
  const apiAppId = typeof envelope.api_app_id === "string" ? envelope.api_app_id : null;
  if (!teamId) {
    audit({ provider: "slack", installationId: null, reason: "malformed" });
    return jsonResponse({ error: { code: "invalid-request" } }, 400);
  }
  const installation = withDb((db) => findActiveSlackInstallationByTenant(db, teamId, apiAppId));
  if (
    !installation ||
    !(await verifySlackSignature(deps, installation, raw, timestampHeader, signatureHeader))
  ) {
    audit({ provider: "slack", installationId: installation?.id ?? null, reason: "unauthorized" });
    return unauthorized();
  }

  if (
    !normalized.message ||
    normalized.message.externalTenantId !== installation.externalTenantId
  ) {
    // Verified but not an ingestible message (or a tenant-confused payload):
    // acknowledge without processing.
    audit({ provider: "slack", installationId: installation.id, reason: "malformed" });
    return acknowledge();
  }

  const reason = await ingestConversationMessage(deps, installation, normalized.message);
  audit({ provider: "slack", installationId: installation.id, reason });
  return acknowledge();
}
