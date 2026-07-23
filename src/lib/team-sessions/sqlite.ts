import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

const SCHEMA_VERSION = 2;
const APPLICATION_ID = 0x54585331; // "TXS1"

const CONVERSATION_SCHEMA = `
CREATE TABLE conversation_identities (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
  kind TEXT NOT NULL CHECK (kind IN ('comment', 'suggestion', 'resolution', 'directive')),
  created_sequence INTEGER CHECK (created_sequence IS NULL OR created_sequence >= 1),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  UNIQUE (id, session_id),
  UNIQUE (session_id, created_sequence),
  FOREIGN KEY (session_id, created_sequence)
    REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
) STRICT;

CREATE INDEX conversation_identities_by_session_kind
  ON conversation_identities(session_id, kind, created_sequence);

CREATE TABLE conversation_suggestion_resolutions (
  suggestion_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  resolution_id TEXT NOT NULL UNIQUE,
  resolution_sequence INTEGER NOT NULL CHECK (resolution_sequence >= 1),
  suggestion_version INTEGER NOT NULL CHECK (suggestion_version = 2),
  decision TEXT NOT NULL CHECK (decision IN ('accept', 'accept-edited', 'reject')),
  directive_id TEXT,
  FOREIGN KEY (suggestion_id, session_id)
    REFERENCES conversation_identities(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (resolution_id, session_id)
    REFERENCES conversation_identities(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (directive_id, session_id)
    REFERENCES conversation_identities(id, session_id) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (session_id, resolution_sequence)
    REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
) STRICT;

CREATE TABLE conversation_directives (
  directive_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  author_user_id TEXT NOT NULL,
  queue_sequence INTEGER NOT NULL CHECK (queue_sequence >= 1),
  status TEXT NOT NULL CHECK (status IN ('queued', 'cancelled', 'dispatched')),
  terminal_sequence INTEGER CHECK (terminal_sequence IS NULL OR terminal_sequence >= 1),
  CHECK (
    (status = 'queued' AND terminal_sequence IS NULL) OR
    (status IN ('cancelled', 'dispatched') AND terminal_sequence IS NOT NULL)
  ),
  UNIQUE (session_id, queue_sequence),
  UNIQUE (session_id, terminal_sequence),
  FOREIGN KEY (directive_id, session_id)
    REFERENCES conversation_identities(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (session_id, queue_sequence)
    REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
  FOREIGN KEY (session_id, terminal_sequence)
    REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
) STRICT;

CREATE INDEX conversation_directives_by_author_status
  ON conversation_directives(author_user_id, status, queue_sequence);

CREATE INDEX conversation_directives_by_session_status
  ON conversation_directives(session_id, status, queue_sequence);
`;

const SCHEMA = `
CREATE TABLE teams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;

CREATE TABLE team_memberships (
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'guest')),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  revoked_at_ms INTEGER,
  PRIMARY KEY (team_id, user_id)
) STRICT;

CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  source_ref TEXT,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  UNIQUE (id, team_id)
) STRICT;

CREATE TABLE project_access (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('maintainer', 'contributor')),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  revoked_at_ms INTEGER,
  PRIMARY KEY (project_id, user_id)
) STRICT;

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
  status TEXT NOT NULL CHECK (status IN ('active', 'awaiting_assignee', 'ended')),
  steering_policy TEXT NOT NULL CHECK (steering_policy IN ('single', 'shared')),
  access_revision INTEGER NOT NULL DEFAULT 1 CHECK (access_revision >= 1),
  assignee_revision INTEGER NOT NULL DEFAULT 1 CHECK (assignee_revision >= 1),
  supervision_revision INTEGER NOT NULL DEFAULT 1 CHECK (supervision_revision >= 1),
  steering_revision INTEGER NOT NULL DEFAULT 1 CHECK (steering_revision >= 1),
  control_revision INTEGER NOT NULL DEFAULT 1 CHECK (control_revision >= 1),
  control_epoch INTEGER NOT NULL DEFAULT 1 CHECK (control_epoch >= 1),
  runtime_authorization_generation INTEGER NOT NULL DEFAULT 1
    CHECK (runtime_authorization_generation >= 1),
  runtime_authorization_state TEXT NOT NULL DEFAULT 'enforced'
    CHECK (runtime_authorization_state IN ('enforced', 'pending', 'quarantined')),
  next_sequence INTEGER NOT NULL DEFAULT 1 CHECK (next_sequence >= 1),
  runtime_kind TEXT NOT NULL CHECK (runtime_kind = 'local-tmux'),
  isolation TEXT NOT NULL CHECK (isolation = 'trusted-shared-host'),
  tmux_name TEXT NOT NULL CHECK (length(tmux_name) BETWEEN 1 AND 128),
  yolo_eligible INTEGER NOT NULL DEFAULT 0 CHECK (yolo_eligible = 0),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  UNIQUE (team_id, name),
  UNIQUE (tmux_name),
  UNIQUE (id, team_id, project_id),
  FOREIGN KEY (project_id, team_id) REFERENCES projects(id, team_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE session_shares (
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  revoked_at_ms INTEGER,
  PRIMARY KEY (session_id, user_id)
) STRICT;

CREATE TABLE session_participants (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  joined_at_ms INTEGER NOT NULL CHECK (joined_at_ms >= 0),
  revoked_at_ms INTEGER,
  UNIQUE (session_id, user_id),
  UNIQUE (id, session_id, user_id)
) STRICT;

CREATE TABLE session_responsibilities (
  session_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('assignee', 'supervisor', 'steerer', 'controller')),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  granted_at_ms INTEGER NOT NULL CHECK (granted_at_ms >= 0),
  revoked_at_ms INTEGER,
  PRIMARY KEY (session_id, user_id, kind),
  FOREIGN KEY (session_id, user_id) REFERENCES session_participants(session_id, user_id)
    ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX one_active_assignee_per_session
  ON session_responsibilities(session_id)
  WHERE kind = 'assignee' AND status = 'active';

CREATE UNIQUE INDEX one_active_controller_per_session
  ON session_responsibilities(session_id)
  WHERE kind = 'controller' AND status = 'active';

CREATE TABLE session_handoffs (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
  offerer_user_id TEXT NOT NULL,
  recipient_participant_id TEXT NOT NULL,
  recipient_user_id TEXT NOT NULL,
  offered_under_kind TEXT NOT NULL CHECK (offered_under_kind IN ('assignee', 'supervisor')),
  offered_under_version INTEGER NOT NULL CHECK (offered_under_version >= 1),
  recipient_participant_version INTEGER NOT NULL CHECK (recipient_participant_version >= 1),
  base_assignee_revision INTEGER NOT NULL CHECK (base_assignee_revision >= 1),
  context_sequence INTEGER NOT NULL CHECK (context_sequence >= 1),
  status TEXT NOT NULL CHECK (status IN ('offered', 'accepted', 'cancelled', 'expired')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
  briefing_json TEXT NOT NULL CHECK (json_valid(briefing_json)),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  resolved_at_ms INTEGER,
  resolved_by_user_id TEXT,
  cancellation_reason TEXT,
  FOREIGN KEY (session_id, offerer_user_id, offered_under_kind)
    REFERENCES session_responsibilities(session_id, user_id, kind) ON DELETE RESTRICT,
  FOREIGN KEY (recipient_participant_id, session_id, recipient_user_id)
    REFERENCES session_participants(id, session_id, user_id) ON DELETE RESTRICT,
  FOREIGN KEY (session_id, context_sequence)
    REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
) STRICT;

CREATE INDEX offered_handoffs_by_session
  ON session_handoffs(session_id, status, created_at_ms, id);

CREATE TABLE session_invitations (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  membership_role TEXT NOT NULL CHECK (membership_role IN ('member', 'guest')),
  token_digest TEXT NOT NULL UNIQUE CHECK (length(token_digest) = 64),
  status TEXT NOT NULL CHECK (status IN ('active', 'redeemed', 'revoked')),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_access_revision INTEGER NOT NULL CHECK (created_access_revision >= 1),
  expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
  created_by_user_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  redeemed_by_user_id TEXT,
  redeemed_at_ms INTEGER,
  revoked_at_ms INTEGER,
  FOREIGN KEY (session_id, team_id, project_id)
    REFERENCES sessions(id, team_id, project_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE session_user_revocations (
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL,
  last_access_revision INTEGER NOT NULL CHECK (last_access_revision >= 1),
  reason TEXT NOT NULL,
  revoked_at_ms INTEGER NOT NULL CHECK (revoked_at_ms >= 0),
  PRIMARY KEY (session_id, user_id)
) STRICT;

CREATE TABLE session_events (
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
  sequence INTEGER NOT NULL CHECK (sequence >= 1),
  event_id TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  occurred_at_ms INTEGER NOT NULL CHECK (occurred_at_ms >= 0),
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('human', 'system')),
  actor_user_id TEXT NOT NULL,
  actor_display_name TEXT NOT NULL,
  source_scope TEXT NOT NULL,
  source_key TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  PRIMARY KEY (session_id, sequence)
) STRICT;

${CONVERSATION_SCHEMA}

CREATE TABLE kernel_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  next_accepted_sequence INTEGER NOT NULL CHECK (next_accepted_sequence >= 1)
) STRICT;

INSERT INTO kernel_state (singleton, next_accepted_sequence) VALUES (1, 1);

CREATE TABLE accepted_commands (
  source_scope TEXT NOT NULL,
  source_key TEXT NOT NULL,
  payload_digest TEXT NOT NULL CHECK (length(payload_digest) = 64),
  accepted_sequence INTEGER NOT NULL UNIQUE CHECK (accepted_sequence >= 1),
  command_type TEXT NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('human', 'system')),
  actor_user_id TEXT NOT NULL,
  actor_display_name TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  result_json TEXT NOT NULL CHECK (json_valid(result_json)),
  secret_result INTEGER NOT NULL DEFAULT 0 CHECK (secret_result IN (0, 1)),
  accepted_at_ms INTEGER NOT NULL CHECK (accepted_at_ms >= 0),
  PRIMARY KEY (source_scope, source_key)
) STRICT;

CREATE TABLE runtime_outbox (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  session_sequence INTEGER NOT NULL CHECK (session_sequence >= 1),
  kind TEXT NOT NULL CHECK (kind IN (
    'runtime.session.ensure',
    'runtime.session.retire',
    'runtime.authorization.fence'
  )),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
    'pending', 'processing', 'delivered', 'superseded', 'failed'
  )),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  lease_owner TEXT,
  lease_expires_at_ms INTEGER,
  last_error TEXT,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  delivered_at_ms INTEGER,
  UNIQUE (session_id, session_sequence, kind),
  FOREIGN KEY (session_id, session_sequence)
    REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
) STRICT;
`;

export interface OpenTeamSessionDatabaseOptions {
  filename: string;
}

export interface TeamSessionDatabase {
  db: Database.Database;
  close(): void;
}

export function openTeamSessionDatabase(
  options: OpenTeamSessionDatabaseOptions
): TeamSessionDatabase {
  const resolved =
    options.filename === ":memory:" ? options.filename : path.resolve(options.filename);
  let filename: string | undefined;
  if (resolved !== ":memory:") {
    const parent = path.dirname(resolved);
    fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
    filename = resolved;
    const descriptor = fs.openSync(resolved, "a", 0o600);
    fs.closeSync(descriptor);
    fs.chmodSync(resolved, 0o600);
  }

  const db = new Database(resolved);
  secureDatabaseFiles(filename);
  try {
    db.pragma("busy_timeout = 5000");
    db.pragma("foreign_keys = ON");
    db.pragma("trusted_schema = OFF");

    // Version discovery and first initialization share the same write lock so
    // the Next route bundle and custom server can open a fresh database at the
    // same time without both attempting the migration.
    const initializeOrVerify = db.transaction(() => {
      const currentVersion = db.pragma("user_version", { simple: true }) as number;
      const applicationId = db.pragma("application_id", { simple: true }) as number;
      if (currentVersion === 0) {
        const userTables = db
          .prepare(
            `SELECT name FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             LIMIT 1`
          )
          .get();
        if (applicationId !== 0 || userTables) {
          throw new Error("Refusing to initialize a non-empty or claimed SQLite database");
        }
        db.exec(SCHEMA);
        db.pragma(`application_id = ${APPLICATION_ID}`);
        db.pragma(`user_version = ${SCHEMA_VERSION}`);
        return;
      }
      if (applicationId !== APPLICATION_ID) {
        throw new Error("File is not a recognized Team Session database");
      }
      if (currentVersion === 1) {
        migrateConversationSchemaV2(db);
        db.pragma(`user_version = ${SCHEMA_VERSION}`);
        return;
      }
      if (currentVersion !== SCHEMA_VERSION) {
        throw new Error(
          `Unsupported Team Session database schema ${currentVersion}; expected ${SCHEMA_VERSION}`
        );
      }
    });
    initializeOrVerify.immediate();

    const applicationId = db.pragma("application_id", { simple: true }) as number;
    if (applicationId !== APPLICATION_ID) {
      throw new Error("File is not a recognized Team Session database");
    }
    const journalMode = db.pragma("journal_mode = WAL", { simple: true }) as string;
    if (resolved !== ":memory:" && journalMode.toLowerCase() !== "wal") {
      throw new Error("Team Session database requires WAL journal mode");
    }
    db.pragma("synchronous = FULL");
    const synchronous = db.pragma("synchronous", { simple: true }) as number;
    if (synchronous !== 2) {
      throw new Error("Team Session database requires FULL synchronous writes");
    }
    const quickCheck = db.pragma("quick_check", { simple: true }) as string;
    if (quickCheck !== "ok") {
      throw new Error("Team Session database failed its integrity check");
    }
    const foreignKeys = db.pragma("foreign_keys", { simple: true }) as number;
    if (foreignKeys !== 1) {
      throw new Error("Team Session database requires SQLite foreign key enforcement");
    }
    secureDatabaseFiles(filename);
  } catch (error) {
    db.close();
    secureDatabaseFiles(filename);
    throw error;
  }

  let closed = false;
  return {
    db,
    close() {
      if (closed) return;
      closed = true;
      db.close();
      secureDatabaseFiles(filename);
    },
  };
}

interface ConversationMigrationEvent {
  session_id: string;
  sequence: number;
  type: string;
  occurred_at_ms: number;
  actor_user_id: string;
  payload_json: string;
}

function migrateConversationSchemaV2(db: Database.Database): void {
  db.exec(CONVERSATION_SCHEMA);
  const events = db
    .prepare(
      `SELECT session_id, sequence, type, occurred_at_ms, actor_user_id, payload_json
       FROM session_events
       WHERE type IN (
         'comment.added', 'suggestion.added', 'suggestion.resolved',
         'directive.queued', 'directive.cancelled', 'directive.dispatched'
       )
       ORDER BY session_id ASC, sequence ASC`
    )
    .all() as ConversationMigrationEvent[];
  const insertIdentity = db.prepare(
    `INSERT INTO conversation_identities
       (id, session_id, kind, created_sequence, created_at_ms)
     VALUES (?, ?, ?, ?, ?)`
  );
  const insertResolution = db.prepare(
    `INSERT INTO conversation_suggestion_resolutions
       (suggestion_id, session_id, resolution_id, resolution_sequence,
        suggestion_version, decision, directive_id)
     VALUES (?, ?, ?, ?, 2, ?, ?)`
  );
  const insertDirective = db.prepare(
    `INSERT INTO conversation_directives
       (directive_id, session_id, author_user_id, queue_sequence, status, terminal_sequence)
     VALUES (?, ?, ?, ?, 'queued', NULL)`
  );
  const closeDirective = db.prepare(
    `UPDATE conversation_directives
     SET status = ?, terminal_sequence = ?
     WHERE directive_id = ? AND session_id = ? AND status = 'queued'`
  );

  for (const event of events) {
    const payload = parseMigrationPayload(event);
    switch (event.type) {
      case "comment.added":
        insertIdentity.run(
          migrationIdentifier(payload, "commentId", event),
          event.session_id,
          "comment",
          event.sequence,
          event.occurred_at_ms
        );
        break;
      case "suggestion.added":
        insertIdentity.run(
          migrationIdentifier(payload, "suggestionId", event),
          event.session_id,
          "suggestion",
          event.sequence,
          event.occurred_at_ms
        );
        break;
      case "suggestion.resolved": {
        const suggestionId = migrationIdentifier(payload, "suggestionId", event);
        const resolutionId = migrationIdentifier(payload, "resolutionId", event);
        const decision = migrationDecision(payload.resolution, event);
        const directiveId =
          decision === "reject" ? null : migrationIdentifier(payload, "directiveId", event);
        if (decision === "reject" && payload.directiveId !== undefined) {
          throw migrationError(event, "rejected Suggestion unexpectedly references a Directive");
        }
        insertIdentity.run(
          resolutionId,
          event.session_id,
          "resolution",
          event.sequence,
          event.occurred_at_ms
        );
        insertResolution.run(
          suggestionId,
          event.session_id,
          resolutionId,
          event.sequence,
          decision,
          directiveId
        );
        break;
      }
      case "directive.queued": {
        const directiveId = migrationIdentifier(payload, "directiveId", event);
        if (payload.status !== "queued") {
          throw migrationError(event, "Directive queue status is invalid");
        }
        insertIdentity.run(
          directiveId,
          event.session_id,
          "directive",
          event.sequence,
          event.occurred_at_ms
        );
        insertDirective.run(directiveId, event.session_id, event.actor_user_id, event.sequence);
        break;
      }
      case "directive.cancelled":
      case "directive.dispatched": {
        const directiveId = migrationIdentifier(payload, "directiveId", event);
        const status = event.type === "directive.cancelled" ? "cancelled" : "dispatched";
        const updated = closeDirective.run(status, event.sequence, directiveId, event.session_id);
        if (updated.changes !== 1) {
          throw migrationError(event, "Directive terminal state has no unique queued predecessor");
        }
        break;
      }
    }
  }

  const overAuthorLimit = db
    .prepare(
      `SELECT author_user_id, COUNT(*) AS count
       FROM conversation_directives WHERE status = 'queued'
       GROUP BY author_user_id HAVING COUNT(*) > 64 LIMIT 1`
    )
    .get() as { author_user_id: string; count: number } | undefined;
  if (overAuthorLimit) {
    throw new Error(
      `Cannot migrate: User ${overAuthorLimit.author_user_id} has ${overAuthorLimit.count} queued Directives`
    );
  }
  const overSessionLimit = db
    .prepare(
      `SELECT session_id, COUNT(*) AS count
       FROM conversation_directives WHERE status = 'queued'
       GROUP BY session_id HAVING COUNT(*) > 256 LIMIT 1`
    )
    .get() as { session_id: string; count: number } | undefined;
  if (overSessionLimit) {
    throw new Error(
      `Cannot migrate: Session ${overSessionLimit.session_id} has ${overSessionLimit.count} queued Directives`
    );
  }
}

function parseMigrationPayload(event: ConversationMigrationEvent): Record<string, unknown> {
  try {
    const value = JSON.parse(event.payload_json) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("not an object");
    }
    return value as Record<string, unknown>;
  } catch {
    throw migrationError(event, "event payload is invalid");
  }
}

function migrationIdentifier(
  payload: Record<string, unknown>,
  key: string,
  event: ConversationMigrationEvent
): string {
  const value = payload[key];
  if (typeof value !== "string" || !value || value.length > 300) {
    throw migrationError(event, `${key} is invalid`);
  }
  return value;
}

function migrationDecision(value: unknown, event: ConversationMigrationEvent): string {
  if (value !== "accept" && value !== "accept-edited" && value !== "reject") {
    throw migrationError(event, "Suggestion resolution is invalid");
  }
  return value;
}

function migrationError(event: ConversationMigrationEvent, detail: string): Error {
  return new Error(
    `Cannot migrate Team Session ${event.session_id} event ${event.sequence}: ${detail}`
  );
}

function secureDatabaseFiles(filename: string | undefined): void {
  if (!filename || process.platform === "win32") return;
  for (const candidate of [filename, `${filename}-wal`, `${filename}-shm`, `${filename}-journal`]) {
    if (fs.existsSync(candidate)) fs.chmodSync(candidate, 0o600);
  }
}
