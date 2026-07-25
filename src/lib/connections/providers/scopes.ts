/**
 * Least-privilege reviewed scopes and capabilities for provider Channel
 * Installations and Identity Connections (Slice 8E, decision 2).
 *
 * A Channel Installation's `reviewedScopes` bound what a Link Challenge may
 * request, and completion accepts only a granted set exactly equal to the
 * requested set (8B). These constants keep both providers pinned to the minimum
 * the typed proxy operations and event subscriptions actually need.
 */

/**
 * Slack bot installation scopes: exactly what the typed proxy operations need.
 * `chat:write` backs `slack.chat.postMessage`/`chat.update`; `channels:read`
 * backs `slack.conversations.info`. The identity-only scopes back Sign in with
 * Slack linking and are a subset of the reviewed set so a Link Challenge can
 * request them.
 */
export const SLACK_BOT_SCOPES: readonly string[] = Object.freeze(["chat:write", "channels:read"]);

/** Identity-only linking scopes (Sign in with Slack / OIDC). */
export const SLACK_IDENTITY_LINK_SCOPES: readonly string[] = Object.freeze(["openid", "profile"]);

/**
 * The reviewed scope set stored on a Slack Channel Installation. It is the union
 * of the bot scopes and the identity-only linking scopes, so linking can request
 * the identity subset while the installation credential is limited to the bot
 * scopes the proxy uses.
 */
export const SLACK_INSTALLATION_REVIEWED_SCOPES: readonly string[] = Object.freeze([
  ...SLACK_BOT_SCOPES,
  ...SLACK_IDENTITY_LINK_SCOPES,
]);

/**
 * Slack event subscriptions the installation is reviewed to receive. These are
 * modeled as capabilities (not OAuth scopes): the app receives only these two
 * event types over the Events API webhook.
 */
export const SLACK_INSTALLATION_CAPABILITIES: readonly string[] = Object.freeze([
  "events:message.channels",
  "events:app_mention",
]);

/**
 * Telegram has no OAuth scopes; the bot's fixed capability set is modeled as the
 * reviewed capabilities. `identity:telegram` is the linking scope a deep-link
 * `/start` Link Challenge requests to attribute one Telegram user to a User.
 */
export const TELEGRAM_BOT_CAPABILITIES: readonly string[] = Object.freeze([
  "bot:send-message",
  "bot:edit-message",
  "bot:receive-updates",
  "bot:get-file",
]);

export const TELEGRAM_IDENTITY_LINK_SCOPES: readonly string[] = Object.freeze([
  "identity:telegram",
]);

/**
 * The reviewed scope set stored on a Telegram Channel Installation. The bot
 * capabilities double as scopes (there is no separate scope namespace) plus the
 * identity linking scope so a `/start` challenge can request it.
 */
export const TELEGRAM_INSTALLATION_REVIEWED_SCOPES: readonly string[] = Object.freeze([
  ...TELEGRAM_BOT_CAPABILITIES,
  ...TELEGRAM_IDENTITY_LINK_SCOPES,
]);

export const TELEGRAM_INSTALLATION_CAPABILITIES = TELEGRAM_BOT_CAPABILITIES;
