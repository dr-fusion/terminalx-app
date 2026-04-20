/**
 * Structured security audit logging for TerminalX.
 * Logs security-sensitive events with timestamp, user, and action context.
 */

export type AuditEvent =
  | "login_success"
  | "login_failed"
  | "logout"
  | "user_created"
  | "user_deleted"
  | "user_role_changed"
  | "session_created"
  | "session_deleted"
  | "file_uploaded"
  | "terminal_connected"
  | "terminal_disconnected"
  | "ws_origin_rejected"
  | "ws_auth_failed"
  | "rate_limited"
  | "snippet_created"
  | "snippet_deleted"
  | "replay_started"
  | "replay_opened"
  | "log_access_denied"
  | "jwt_verify_failed";

interface AuditEntry {
  timestamp: string;
  event: AuditEvent;
  username?: string;
  userId?: string;
  detail?: string;
}

export function audit(event: AuditEvent, context?: Omit<AuditEntry, "timestamp" | "event">): void {
  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    event,
    ...context,
  };
  // Structured JSON log to stdout for easy parsing by log aggregators
  console.log(`[audit] ${JSON.stringify(entry)}`);
}
