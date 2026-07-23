import { handleTelegramUpdate } from "./bot";

export type TelegramUpdateHandler = (update: object) => Promise<void>;

export type TelegramWebhookAcceptance =
  | { accepted: true; processing: Promise<void> }
  | { accepted: false; errorMessage: string };

/**
 * One shared sync boundary for both HTTP implementations. The handler commits
 * the inbound audit row before returning a dispatch promise, so a thrown error
 * means callers must return a retryable response instead of acknowledging it.
 */
export function acceptTelegramWebhookUpdate(
  update: object,
  handler: TelegramUpdateHandler = handleTelegramUpdate
): TelegramWebhookAcceptance {
  try {
    return { accepted: true, processing: handler(update) };
  } catch (error) {
    return {
      accepted: false,
      errorMessage: error instanceof Error ? error.message : String(error),
    };
  }
}
