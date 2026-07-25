import * as fs from "fs";
import * as path from "path";
import { ensureSecureDir } from "@/lib/secure-dir";

export interface TelegramConfig {
  enabled?: boolean;
  botToken?: string;
  webhookUrl?: string;
  webhookSecret?: string;
  allowedUsers?: string;
  forumChatId?: number;
  maxTopics?: number;
}

export interface SanitizedTelegramConfig {
  enabled: boolean;
  configured: boolean;
  botTokenSet: boolean;
  botTokenPreview: string | null;
  webhookUrl: string;
  webhookSecretSet: boolean;
  allowedUsers: string;
  forumChatId: number | null;
  maxTopics: number;
}

const DATA_DIR = path.join(process.cwd(), "data");
const CONFIG_FILE = path.join(DATA_DIR, "telegram-config.json");

let writeLock: Promise<void> = Promise.resolve();
function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = writeLock.then(fn, fn);
  writeLock = next.then(
    () => {},
    () => {}
  );
  return next;
}

function readFileConfig(): TelegramConfig {
  try {
    const raw = fs.readFileSync(CONFIG_FILE, "utf-8");
    return JSON.parse(raw) as TelegramConfig;
  } catch {
    return {};
  }
}

function envConfig(): TelegramConfig {
  const forumChatIdRaw = process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID;
  const maxTopicsRaw = process.env.TERMINALX_TELEGRAM_MAX_TOPICS;
  const forumChatId = forumChatIdRaw ? Number(forumChatIdRaw) : undefined;
  const maxTopics = maxTopicsRaw ? Number(maxTopicsRaw) : undefined;
  return {
    enabled: process.env.TERMINALX_TELEGRAM_ENABLED
      ? process.env.TERMINALX_TELEGRAM_ENABLED === "true"
      : undefined,
    botToken: process.env.TERMINALX_TELEGRAM_BOT_TOKEN,
    webhookUrl: process.env.TERMINALX_TELEGRAM_WEBHOOK_URL,
    webhookSecret: process.env.TERMINALX_TELEGRAM_WEBHOOK_SECRET,
    allowedUsers: process.env.TERMINALX_TELEGRAM_ALLOWED_USERS,
    forumChatId: Number.isFinite(forumChatId) && forumChatId !== 0 ? forumChatId : undefined,
    maxTopics: Number.isFinite(maxTopics) && maxTopics && maxTopics > 0 ? maxTopics : undefined,
  };
}

function normalize(config: TelegramConfig): TelegramConfig {
  return {
    enabled: config.enabled,
    botToken: config.botToken?.trim() || undefined,
    webhookUrl: config.webhookUrl?.trim() || undefined,
    webhookSecret: config.webhookSecret?.trim() || undefined,
    allowedUsers: config.allowedUsers?.trim() || undefined,
    forumChatId:
      Number.isFinite(config.forumChatId) && config.forumChatId !== 0
        ? config.forumChatId
        : undefined,
    maxTopics:
      Number.isFinite(config.maxTopics) && config.maxTopics && config.maxTopics > 0
        ? Math.floor(config.maxTopics)
        : undefined,
  };
}

function mergedConfig(): TelegramConfig {
  return normalize({
    ...envConfig(),
    ...readFileConfig(),
  });
}

export function getTelegramConfig(): Required<TelegramConfig> {
  const config = mergedConfig();
  return {
    enabled: config.enabled ?? Boolean(config.botToken),
    botToken: config.botToken ?? "",
    webhookUrl: config.webhookUrl ?? "",
    webhookSecret: config.webhookSecret ?? "",
    allowedUsers: config.allowedUsers ?? "",
    forumChatId: config.forumChatId ?? 0,
    maxTopics: config.maxTopics ?? Number.POSITIVE_INFINITY,
  };
}

export function isTelegramConfigured(): boolean {
  const config = getTelegramConfig();
  return Boolean(
    config.enabled &&
    config.botToken &&
    config.webhookUrl &&
    config.webhookSecret &&
    config.allowedUsers &&
    config.forumChatId
  );
}

export function telegramConfigHasAnyValue(): boolean {
  const config = mergedConfig();
  return Boolean(
    config.botToken ||
    config.webhookUrl ||
    config.webhookSecret ||
    config.allowedUsers ||
    config.forumChatId
  );
}

export async function updateTelegramConfig(patch: TelegramConfig): Promise<TelegramConfig> {
  return withLock(async () => {
    ensureSecureDir(DATA_DIR);
    const existing = readFileConfig();
    const next = normalize({ ...existing, ...patch });
    const tmp = CONFIG_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(next, null, 2), { encoding: "utf-8", mode: 0o600 });
    fs.renameSync(tmp, CONFIG_FILE);
    return getTelegramConfig();
  });
}

export function sanitizeTelegramConfig(): SanitizedTelegramConfig {
  const config = getTelegramConfig();
  const token = config.botToken;
  return {
    enabled: config.enabled,
    configured: isTelegramConfigured(),
    botTokenSet: Boolean(token),
    botTokenPreview: token ? `...${token.slice(-6)}` : null,
    webhookUrl: config.webhookUrl,
    webhookSecretSet: Boolean(config.webhookSecret),
    allowedUsers: config.allowedUsers,
    forumChatId: config.forumChatId || null,
    maxTopics: Number.isFinite(config.maxTopics) ? config.maxTopics : 10,
  };
}

export function telegramConfigFingerprint(): string {
  return JSON.stringify(getTelegramConfig());
}

/**
 * Whether the legacy host-global Telegram integration is enabled.
 *
 * The legacy integration is deprecated: it is a single host-global bot token and
 * username allowlist that predates the Phase 8 connection authority and never
 * feeds it. It backs a live production deployment, so it defaults to today's
 * behavior (enabled). Set `TERMINALX_LEGACY_TELEGRAM=false` (or `0`/`off`/`no`)
 * to disable it entirely. Its full retirement lands with Slice 8F hosted
 * enforcement; hosted Runtimes never get this path.
 */
export function legacyTelegramIntegrationEnabled(): boolean {
  const raw = process.env.TERMINALX_LEGACY_TELEGRAM;
  if (raw === undefined) return true;
  const normalized = raw.trim().toLowerCase();
  return !(
    normalized === "false" ||
    normalized === "0" ||
    normalized === "off" ||
    normalized === "no"
  );
}

export function parseTelegramAllowedUsers(raw: string): Map<number, string> {
  const map = new Map<number, string>();
  for (const entry of raw.split(",")) {
    const [tgId, username] = entry.split(":").map((s) => s.trim());
    if (!tgId || !username) continue;
    const id = Number(tgId);
    if (!Number.isFinite(id)) continue;
    map.set(id, username);
  }
  return map;
}
