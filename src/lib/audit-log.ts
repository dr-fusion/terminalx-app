/**
 * Structured security audit logging for TerminalX.
 * Logs security-sensitive events with timestamp, user, and action context.
 */

export type AuditEvent =
  | "login_success"
  | "login_failed"
  | "logout"
  | "logout_failed"
  | "user_created"
  | "user_deleted"
  | "user_role_changed"
  | "session_created"
  | "session_deleted"
  | "file_uploaded"
  | "file_access_denied"
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
  | "jwt_verify_failed"
  | "telegram_config_updated"
  | "telegram_topic_view_updated"
  | "pairing_code_created"
  | "pair_success"
  | "pair_failed"
  | "device_revoked"
  | "device_revocation_failed"
  | "device_registry_read_failed"
  // Workspace config (feature #5):
  | "workspace_config_edited"
  | "workspace_script_run"
  | "workspace_setup_run"
  // Project sidebar (feature #12): project registration + deletion.
  | "project_registered"
  | "project_deleted"
  // Models & harness settings (feature #11): repo-scope settings write.
  | "settings_repo_updated"
  // OpenCode provider catalog (feature #8): records only the provider id + scope,
  // never a provider secret (auth is delegated to OpenCode's config / .env).
  | "opencode_provider_configured"
  | "opencode_provider_removed";

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
