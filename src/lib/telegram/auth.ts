import { getUserByUsername } from "@/lib/users";
import { getAuthMode } from "@/lib/auth-config";

export interface BotIdentity {
  username: string;
  role: "admin" | "user";
}

/**
 * Parse `TERMINALX_TELEGRAM_ALLOWED_USERS` into a `tg_user_id → terminalx_username`
 * map. Format: comma-separated `123456:paresh,234567:admin`.
 *
 * v1 ships with a single user expected; the multi-entry format is forward-compat.
 */
function parseAllowedUsers(raw: string | undefined): Map<number, string> {
  const map = new Map<number, string>();
  if (!raw) return map;
  for (const entry of raw.split(",")) {
    const [tgId, username] = entry.split(":").map((s) => s.trim());
    if (!tgId || !username) continue;
    const id = Number(tgId);
    if (!Number.isFinite(id)) continue;
    map.set(id, username);
  }
  return map;
}

let cached: Map<number, string> | null = null;
function allowedUsers(): Map<number, string> {
  if (!cached) cached = parseAllowedUsers(process.env.TERMINALX_TELEGRAM_ALLOWED_USERS);
  return cached;
}

/**
 * Resolve a Telegram user id to a TerminalX identity. Returns null if the
 * user is not allow-listed. Looks up the user record so we can pick up the
 * role for `canAccessSession` checks; if the auth mode doesn't store users
 * (e.g. `none`, `password`), we synthesize an admin identity.
 */
export async function resolveTelegramIdentity(
  tgUserId: number | undefined
): Promise<BotIdentity | null> {
  if (!tgUserId) return null;
  const username = allowedUsers().get(tgUserId);
  if (!username) return null;

  const mode = getAuthMode();
  if (mode === "local") {
    const user = await getUserByUsername(username);
    if (!user) return null;
    return { username, role: user.role };
  }
  // For `none` / `password` / `google`, treat the env-mapped user as admin.
  // The TG allowlist is the gating mechanism in those modes.
  return { username, role: "admin" };
}

/**
 * True only when both the bot token and at least one allowed user are
 * configured. Used at server boot to decide whether to start the bot at all.
 */
export function botIsConfigured(): boolean {
  const token = process.env.TERMINALX_TELEGRAM_BOT_TOKEN;
  const hasUsers = allowedUsers().size > 0;
  return Boolean(token && hasUsers && getTelegramForumChatId() !== null);
}

export function telegramAllowedUserCount(): number {
  return allowedUsers().size;
}

export function getTelegramForumChatId(): number | null {
  const raw = process.env.TERMINALX_TELEGRAM_FORUM_CHAT_ID;
  if (!raw) return null;
  const chatId = Number(raw);
  return Number.isFinite(chatId) && chatId !== 0 ? chatId : null;
}
