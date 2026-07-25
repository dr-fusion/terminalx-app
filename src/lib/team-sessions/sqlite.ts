import * as fs from "fs";
import * as path from "path";
import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import { digestRuntimeCompensationIncident } from "../runtime/runtime-compensation-incident";
import { RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS } from "../runtime/runtime-receipt-observation-contract";
import { isValidTmuxSessionName } from "../tmux";

const SCHEMA_VERSION = 11;
const PRE_RUNTIME_START_SCHEMA_VERSION = 4;
const RUNTIME_START_SCHEMA_VERSION = 5;
const RUNTIME_RECEIPT_FOLLOW_SCHEMA_VERSION = 6;
const RUNTIME_COMPENSATION_SCHEMA_VERSION = 7;
const RUNTIME_ASSIGNMENT_OUTBOX_INTERLOCK_SCHEMA_VERSION = 8;
const HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION = 9;
const PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION = 10;
const CANONICAL_IDENTITY_SCHEMA_VERSION = 11;
const APPLICATION_ID = 0x54585331; // "TXS1"

const CANONICAL_IDENTITY_SCHEMA_V11 = `
CREATE TABLE users (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 300),
  username TEXT NOT NULL CHECK (length(username) BETWEEN 1 AND 320),
  display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 320),
  legacy_role TEXT NOT NULL CHECK (legacy_role IN ('admin', 'user')),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  generation INTEGER NOT NULL CHECK (generation >= 1),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
  last_login_at_ms INTEGER CHECK (last_login_at_ms IS NULL OR last_login_at_ms >= created_at_ms),
  revoked_at_ms INTEGER,
  CHECK (
    (status = 'active' AND revoked_at_ms IS NULL) OR
    (status = 'revoked' AND revoked_at_ms IS NOT NULL AND revoked_at_ms >= created_at_ms)
  )
) STRICT;

CREATE INDEX users_by_status_username ON users(status, username, id);

CREATE TRIGGER users_identity_immutable
BEFORE UPDATE OF id, created_at_ms ON users
BEGIN
  SELECT RAISE(ABORT, 'Canonical User identity is immutable');
END;

CREATE TRIGGER users_immutable_delete
BEFORE DELETE ON users
BEGIN
  SELECT RAISE(ABORT, 'Canonical User history is immutable');
END;

CREATE TRIGGER users_revocation_irreversible
BEFORE UPDATE OF status ON users
WHEN OLD.status = 'revoked' AND NEW.status <> 'revoked'
BEGIN
  SELECT RAISE(ABORT, 'Canonical User revoked state is irreversible');
END;

CREATE TRIGGER users_generation_monotonic
BEFORE UPDATE ON users
WHEN
  NEW.generation < OLD.generation OR
  NEW.generation > OLD.generation + 1 OR
  (
    (
      NEW.username IS NOT OLD.username OR
      NEW.display_name IS NOT OLD.display_name OR
      NEW.legacy_role IS NOT OLD.legacy_role OR
      NEW.status IS NOT OLD.status
    ) AND NEW.generation <> OLD.generation + 1
  ) OR
  (
    NEW.username IS OLD.username AND
    NEW.display_name IS OLD.display_name AND
    NEW.legacy_role IS OLD.legacy_role AND
    NEW.status IS OLD.status AND
    NEW.generation <> OLD.generation
  )
BEGIN
  SELECT RAISE(ABORT, 'Canonical User generation transition is invalid');
END;

CREATE TRIGGER users_timestamps_monotonic
BEFORE UPDATE ON users
WHEN
  NEW.updated_at_ms < OLD.updated_at_ms OR
  (
    OLD.last_login_at_ms IS NOT NULL AND
    (NEW.last_login_at_ms IS NULL OR NEW.last_login_at_ms < OLD.last_login_at_ms)
  )
BEGIN
  SELECT RAISE(ABORT, 'Canonical User timestamp transition is invalid');
END;

CREATE TABLE auth_identities (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 300),
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  provider TEXT NOT NULL CHECK (provider IN ('local', 'google', 'password')),
  subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 1024),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  generation INTEGER NOT NULL CHECK (generation >= 1),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
  last_authenticated_at_ms INTEGER CHECK (
    last_authenticated_at_ms IS NULL OR last_authenticated_at_ms >= created_at_ms
  ),
  revoked_at_ms INTEGER,
  CHECK (
    (status = 'active' AND revoked_at_ms IS NULL) OR
    (status = 'revoked' AND revoked_at_ms IS NOT NULL AND revoked_at_ms >= created_at_ms)
  ),
  UNIQUE (provider, subject),
  UNIQUE (id, user_id)
) STRICT;

CREATE INDEX auth_identities_by_user_status
  ON auth_identities(user_id, status, provider, id);

CREATE TRIGGER auth_identities_identity_immutable
BEFORE UPDATE OF id, user_id, provider, subject, created_at_ms ON auth_identities
BEGIN
  SELECT RAISE(ABORT, 'Authentication identity provider subject is immutable');
END;

CREATE TRIGGER auth_identities_immutable_delete
BEFORE DELETE ON auth_identities
BEGIN
  SELECT RAISE(ABORT, 'Authentication identity history is immutable');
END;

CREATE TRIGGER auth_identities_revocation_irreversible
BEFORE UPDATE OF status ON auth_identities
WHEN OLD.status = 'revoked' AND NEW.status <> 'revoked'
BEGIN
  SELECT RAISE(ABORT, 'Authentication identity revoked state is irreversible');
END;

CREATE TRIGGER auth_identities_generation_monotonic
BEFORE UPDATE ON auth_identities
WHEN
  NEW.generation < OLD.generation OR
  NEW.generation > OLD.generation + 1 OR
  (NEW.status IS NOT OLD.status AND NEW.generation <> OLD.generation + 1) OR
  (NEW.status IS OLD.status AND NEW.generation <> OLD.generation)
BEGIN
  SELECT RAISE(ABORT, 'Authentication identity generation transition is invalid');
END;

CREATE TRIGGER auth_identities_timestamps_monotonic
BEFORE UPDATE ON auth_identities
WHEN
  NEW.updated_at_ms < OLD.updated_at_ms OR
  (
    OLD.last_authenticated_at_ms IS NOT NULL AND
    (
      NEW.last_authenticated_at_ms IS NULL OR
      NEW.last_authenticated_at_ms < OLD.last_authenticated_at_ms
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'Authentication identity timestamp transition is invalid');
END;

CREATE TABLE local_auth_credentials (
  auth_identity_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL CHECK (length(password_hash) BETWEEN 20 AND 4096),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
  FOREIGN KEY (auth_identity_id, user_id)
    REFERENCES auth_identities(id, user_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE identity_migrations (
  migration_key TEXT PRIMARY KEY CHECK (length(migration_key) BETWEEN 1 AND 200),
  source_digest TEXT NOT NULL CHECK (length(source_digest) = 64),
  imported_count INTEGER NOT NULL CHECK (imported_count >= 0),
  completed_at_ms INTEGER NOT NULL CHECK (completed_at_ms >= 0)
) STRICT;

CREATE TRIGGER identity_migrations_immutable_update
BEFORE UPDATE ON identity_migrations
BEGIN
  SELECT RAISE(ABORT, 'Identity migration history is immutable');
END;

CREATE TRIGGER identity_migrations_immutable_delete
BEFORE DELETE ON identity_migrations
BEGIN
  SELECT RAISE(ABORT, 'Identity migration history is immutable');
END;
`;

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

const AGENT_RUN_SCHEMA = `
CREATE TRIGGER sessions_runtime_configuration_immutable
BEFORE UPDATE OF runtime_kind, isolation, tmux_name, yolo_eligible ON sessions
BEGIN
  SELECT RAISE(ABORT, 'Session Runtime configuration is immutable');
END;

CREATE TRIGGER sessions_runtime_authorization_monotonic
BEFORE UPDATE OF runtime_authorization_generation, runtime_authorization_state ON sessions
WHEN
  NEW.runtime_authorization_generation < OLD.runtime_authorization_generation OR
  NEW.runtime_authorization_generation > OLD.runtime_authorization_generation + 1 OR
  (
    NEW.runtime_authorization_generation = OLD.runtime_authorization_generation AND
    CASE NEW.runtime_authorization_state
      WHEN 'pending' THEN 0 WHEN 'enforced' THEN 1 WHEN 'quarantined' THEN 2
    END < CASE OLD.runtime_authorization_state
      WHEN 'pending' THEN 0 WHEN 'enforced' THEN 1 WHEN 'quarantined' THEN 2
    END
  ) OR
  (
    NEW.runtime_authorization_generation = OLD.runtime_authorization_generation + 1 AND
    NEW.runtime_authorization_state = 'enforced'
  )
BEGIN
  SELECT RAISE(ABORT, 'Invalid Session Runtime authorization transition');
END;

CREATE TABLE runtime_assignments (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation >= 1),
  runtime_kind TEXT NOT NULL CHECK (runtime_kind = 'local-tmux'),
  sandbox_id TEXT NOT NULL CHECK (length(sandbox_id) BETWEEN 1 AND 300),
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL CHECK (length(runtime_principal_id) BETWEEN 1 AND 300),
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  status TEXT NOT NULL CHECK (status IN (
    'provisioning', 'ready', 'checkpointing', 'recovering',
    'quarantined', 'retired', 'failed'
  )),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  retired_at_ms INTEGER,
  CHECK (
    (status = 'retired' AND retired_at_ms IS NOT NULL) OR
    (status <> 'retired' AND retired_at_ms IS NULL)
  ),
  UNIQUE (session_id, generation),
  UNIQUE (id, session_id),
  UNIQUE (id, generation, sandbox_id, sandbox_generation, runtime_principal_id),
  UNIQUE (
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ),
  FOREIGN KEY (session_id, team_id, project_id)
    REFERENCES sessions(id, team_id, project_id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER runtime_assignments_identity_immutable
BEFORE UPDATE OF id, session_id, team_id, project_id, generation, runtime_kind,
  sandbox_id, sandbox_generation, runtime_principal_id, created_at_ms
ON runtime_assignments
BEGIN
  SELECT RAISE(ABORT, 'Runtime Assignment identity is immutable');
END;

CREATE TRIGGER runtime_assignments_authorization_monotonic
BEFORE UPDATE OF runtime_authorization_generation ON runtime_assignments
WHEN NEW.runtime_authorization_generation < OLD.runtime_authorization_generation
BEGIN
  SELECT RAISE(ABORT, 'Runtime authorization generation cannot move backwards');
END;

CREATE TRIGGER runtime_assignments_valid_status_transition
BEFORE UPDATE OF status ON runtime_assignments
WHEN NOT (
  (OLD.status = 'provisioning' AND NEW.status IN (
    'provisioning', 'ready', 'quarantined', 'retired', 'failed'
  )) OR
  (OLD.status = 'ready' AND NEW.status IN (
    'ready', 'checkpointing', 'recovering', 'quarantined', 'retired', 'failed'
  )) OR
  (OLD.status = 'checkpointing' AND NEW.status IN (
    'checkpointing', 'ready', 'recovering', 'quarantined', 'retired', 'failed'
  )) OR
  (OLD.status = 'recovering' AND NEW.status IN (
    'recovering', 'ready', 'quarantined', 'retired', 'failed'
  )) OR
  (OLD.status = 'quarantined' AND NEW.status IN ('quarantined', 'retired', 'failed')) OR
  (OLD.status = 'retired' AND NEW.status = 'retired') OR
  (OLD.status = 'failed' AND NEW.status = 'failed')
)
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime Assignment status transition');
END;

CREATE UNIQUE INDEX one_current_runtime_assignment_per_session
  ON runtime_assignments(session_id)
  WHERE status IN ('provisioning', 'ready', 'checkpointing', 'recovering', 'quarantined')
    AND NOT (runtime_kind = 'daytona' AND status = 'recovering');

CREATE TABLE runtime_authorization_epochs (
  session_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation >= 1),
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  PRIMARY KEY (session_id, generation),
  UNIQUE (
    session_id, generation, runtime_assignment_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ),
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER runtime_authorization_epochs_immutable_update
BEFORE UPDATE ON runtime_authorization_epochs
BEGIN
  SELECT RAISE(ABORT, 'Runtime authorization epochs are immutable');
END;

CREATE TRIGGER runtime_authorization_epochs_immutable_delete
BEFORE DELETE ON runtime_authorization_epochs
BEGIN
  SELECT RAISE(ABORT, 'Runtime authorization epochs are immutable');
END;

CREATE TABLE agent_runs (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  runtime_assignment_id TEXT NOT NULL,
  lifecycle TEXT NOT NULL CHECK (lifecycle IN (
    'active', 'pausing', 'paused', 'agent-work-finished',
    'completed', 'failed', 'stopped', 'emergency-stopped'
  )),
  state_version INTEGER NOT NULL DEFAULT 1 CHECK (state_version >= 1),
  current_policy_revision INTEGER NOT NULL CHECK (current_policy_revision >= 1),
  current_goal_set_revision INTEGER NOT NULL CHECK (current_goal_set_revision >= 1),
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  final_review_version INTEGER NOT NULL DEFAULT 1 CHECK (final_review_version >= 1),
  created_by_user_id TEXT NOT NULL CHECK (length(created_by_user_id) BETWEEN 1 AND 300),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
  terminal_at_ms INTEGER,
  CHECK (
    (lifecycle IN ('completed', 'failed', 'stopped', 'emergency-stopped')
      AND terminal_at_ms IS NOT NULL) OR
    (lifecycle IN ('active', 'pausing', 'paused', 'agent-work-finished')
      AND terminal_at_ms IS NULL)
  ),
  UNIQUE (id, session_id),
  FOREIGN KEY (session_id, team_id, project_id)
    REFERENCES sessions(id, team_id, project_id) ON DELETE RESTRICT,
  FOREIGN KEY (runtime_assignment_id, session_id)
    REFERENCES runtime_assignments(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (id, current_policy_revision)
    REFERENCES run_policy_revisions(agent_run_id, revision)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (id, current_goal_set_revision)
    REFERENCES goal_sets(agent_run_id, revision)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (session_id, runtime_authorization_generation)
    REFERENCES runtime_authorization_epochs(session_id, generation)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TRIGGER agent_runs_authorization_monotonic
BEFORE UPDATE OF runtime_authorization_generation ON agent_runs
WHEN NEW.runtime_authorization_generation < OLD.runtime_authorization_generation
BEGIN
  SELECT RAISE(ABORT, 'Run Runtime authorization generation cannot move backwards');
END;

CREATE UNIQUE INDEX one_mutable_agent_run_per_session
  ON agent_runs(session_id)
  WHERE lifecycle IN ('active', 'pausing', 'paused', 'agent-work-finished');

CREATE TABLE run_policy_revisions (
  agent_run_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  previous_revision INTEGER,
  digest TEXT NOT NULL CHECK (length(digest) = 64),
  policy_body_digest TEXT NOT NULL CHECK (length(policy_body_digest) = 64),
  mode TEXT NOT NULL CHECK (mode IN ('supervised', 'autonomous', 'yolo')),
  completion_policy TEXT NOT NULL CHECK (completion_policy IN (
    'stop-after-directed-work', 'continue-until-all-goals-achieved'
  )),
  scoped_external_policy_ref TEXT NOT NULL
    CHECK (length(scoped_external_policy_ref) BETWEEN 1 AND 500),
  scoped_external_rules_json TEXT NOT NULL CHECK (
    json_valid(scoped_external_rules_json) AND json_type(scoped_external_rules_json) = 'array'
  ),
  limits_json TEXT NOT NULL CHECK (
    json_valid(limits_json) AND json_type(limits_json) = 'object'
    AND COALESCE(json_extract(limits_json, '$.wallClock.kind'), '') IN ('unconfigured', 'capped')
    AND COALESCE(json_extract(limits_json, '$.modelTokens.kind'), '') IN ('unconfigured', 'capped')
    AND COALESCE(json_extract(limits_json, '$.modelSpend.kind'), '') IN ('unconfigured', 'capped')
    AND COALESCE(json_extract(limits_json, '$.outboundBytes.kind'), '') IN ('unconfigured', 'capped')
    AND COALESCE(json_extract(limits_json, '$.actionCounts.local.kind'), '') IN ('unconfigured', 'capped')
    AND COALESCE(json_extract(limits_json, '$.actionCounts."scoped-external".kind'), '')
      IN ('unconfigured', 'capped')
    AND COALESCE(json_extract(limits_json, '$.actionCounts.protected.kind'), '')
      IN ('unconfigured', 'capped')
    AND COALESCE(json_extract(limits_json, '$.actionCounts.forbidden.kind'), '')
      IN ('unconfigured', 'capped')
  ),
  initial_goal_set_id TEXT NOT NULL CHECK (length(initial_goal_set_id) BETWEEN 1 AND 300),
  initial_goal_set_revision INTEGER NOT NULL CHECK (initial_goal_set_revision >= 1),
  project_ceiling_revision TEXT NOT NULL
    CHECK (length(project_ceiling_revision) BETWEEN 1 AND 300),
  project_ceiling_digest TEXT NOT NULL CHECK (length(project_ceiling_digest) = 64),
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  yolo_confirmation_ref TEXT,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  PRIMARY KEY (agent_run_id, revision),
  UNIQUE (agent_run_id, session_id, revision),
  UNIQUE (
    agent_run_id, session_id, revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation
  ),
  UNIQUE (agent_run_id, digest),
  CHECK (
    (revision = 1 AND previous_revision IS NULL) OR
    (revision > 1 AND previous_revision IS NOT NULL
      AND previous_revision = revision - 1)
  ),
  CHECK (mode <> 'supervised' OR completion_policy = 'stop-after-directed-work'),
  CHECK (
    (mode = 'yolo' AND yolo_confirmation_ref IS NOT NULL) OR
    (mode <> 'yolo' AND yolo_confirmation_ref IS NULL)
  ),
  FOREIGN KEY (agent_run_id, session_id)
    REFERENCES agent_runs(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (agent_run_id, initial_goal_set_id, initial_goal_set_revision)
    REFERENCES goal_sets(agent_run_id, goal_set_id, revision) ON DELETE RESTRICT,
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation, sandbox_id,
    sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    session_id, runtime_authorization_generation, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_authorization_epochs(
    session_id, generation, runtime_assignment_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (agent_run_id, previous_revision)
    REFERENCES run_policy_revisions(agent_run_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER run_policy_revisions_immutable_update
BEFORE UPDATE ON run_policy_revisions
BEGIN
  SELECT RAISE(ABORT, 'Run policy revisions are immutable');
END;

CREATE TRIGGER run_policy_revisions_immutable_delete
BEFORE DELETE ON run_policy_revisions
BEGIN
  SELECT RAISE(ABORT, 'Run policy revisions are immutable');
END;

CREATE TABLE goal_sets (
  goal_set_id TEXT NOT NULL CHECK (length(goal_set_id) BETWEEN 1 AND 300),
  agent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  previous_revision INTEGER,
  digest TEXT NOT NULL CHECK (length(digest) = 64),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  PRIMARY KEY (agent_run_id, revision),
  UNIQUE (goal_set_id, revision),
  UNIQUE (agent_run_id, goal_set_id, revision),
  UNIQUE (agent_run_id, digest),
  CHECK (
    (revision = 1 AND previous_revision IS NULL) OR
    (revision > 1 AND previous_revision IS NOT NULL
      AND previous_revision = revision - 1)
  ),
  FOREIGN KEY (agent_run_id, goal_set_id, previous_revision)
    REFERENCES goal_sets(agent_run_id, goal_set_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER goal_sets_immutable_update
BEFORE UPDATE ON goal_sets
BEGIN
  SELECT RAISE(ABORT, 'Goal Set revisions are immutable');
END;

CREATE TRIGGER goal_sets_immutable_delete
BEFORE DELETE ON goal_sets
BEGIN
  SELECT RAISE(ABORT, 'Goal Set revisions are immutable');
END;

CREATE TABLE goals (
  agent_run_id TEXT NOT NULL,
  goal_set_id TEXT NOT NULL,
  goal_set_revision INTEGER NOT NULL CHECK (goal_set_revision >= 1),
  goal_id TEXT NOT NULL CHECK (length(goal_id) BETWEEN 1 AND 300),
  position INTEGER NOT NULL CHECK (position >= 1),
  version INTEGER NOT NULL CHECK (version >= 1),
  title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 1000),
  acceptance_criteria_json TEXT NOT NULL CHECK (
    json_valid(acceptance_criteria_json) AND json_type(acceptance_criteria_json) = 'array'
  ),
  dependency_goal_ids_json TEXT NOT NULL CHECK (
    json_valid(dependency_goal_ids_json) AND json_type(dependency_goal_ids_json) = 'array'
  ),
  status TEXT NOT NULL CHECK (status IN (
    'pending', 'in-progress', 'blocked', 'provisionally-achieved', 'validated'
  )),
  PRIMARY KEY (goal_set_id, goal_set_revision, goal_id),
  UNIQUE (goal_set_id, goal_set_revision, position),
  UNIQUE (agent_run_id, goal_set_id, goal_set_revision, goal_id, version),
  FOREIGN KEY (agent_run_id, goal_set_id, goal_set_revision)
    REFERENCES goal_sets(agent_run_id, goal_set_id, revision) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER goals_immutable_update
BEFORE UPDATE ON goals
BEGIN
  SELECT RAISE(ABORT, 'Goal snapshots are immutable');
END;

CREATE TRIGGER goals_immutable_delete
BEFORE DELETE ON goals
BEGIN
  SELECT RAISE(ABORT, 'Goal snapshots are immutable');
END;

CREATE TABLE goal_evidence (
  id TEXT PRIMARY KEY,
  agent_run_id TEXT NOT NULL REFERENCES agent_runs(id) ON DELETE RESTRICT,
  goal_set_id TEXT NOT NULL,
  goal_set_revision INTEGER NOT NULL CHECK (goal_set_revision >= 1),
  goal_id TEXT NOT NULL,
  goal_version INTEGER NOT NULL CHECK (goal_version >= 1),
  evidence_ref TEXT NOT NULL CHECK (length(evidence_ref) BETWEEN 1 AND 1000),
  evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 64),
  status TEXT NOT NULL CHECK (status IN ('proposed', 'validated', 'more-work-requested')),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  reviewed_at_ms INTEGER,
  UNIQUE (agent_run_id, evidence_digest),
  CHECK (
    (status = 'proposed' AND reviewed_at_ms IS NULL) OR
    (status IN ('validated', 'more-work-requested')
      AND reviewed_at_ms IS NOT NULL AND reviewed_at_ms >= created_at_ms)
  ),
  FOREIGN KEY (agent_run_id, goal_set_id, goal_set_revision, goal_id, goal_version)
    REFERENCES goals(
      agent_run_id, goal_set_id, goal_set_revision, goal_id, version
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE action_manifests (
  id TEXT PRIMARY KEY,
  version INTEGER NOT NULL CHECK (version = 1),
  session_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  digest TEXT NOT NULL UNIQUE CHECK (length(digest) = 64),
  action_class TEXT NOT NULL CHECK (action_class IN (
    'local', 'scoped-external', 'protected', 'forbidden'
  )),
  provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
  operation TEXT NOT NULL CHECK (length(operation) BETWEEN 1 AND 200),
  exact_target TEXT NOT NULL CHECK (length(exact_target) BETWEEN 1 AND 2000),
  action_schema_id TEXT NOT NULL CHECK (length(action_schema_id) BETWEEN 1 AND 300),
  action_schema_version INTEGER NOT NULL CHECK (action_schema_version >= 1),
  action_schema_digest TEXT NOT NULL CHECK (length(action_schema_digest) = 64),
  canonical_effect_input_digest TEXT NOT NULL CHECK (length(canonical_effect_input_digest) = 64),
  effect_idempotency_key TEXT NOT NULL CHECK (length(effect_idempotency_key) BETWEEN 1 AND 500),
  commit_sha TEXT,
  artifact_digest TEXT,
  credential_ref TEXT,
  expected_effect_json TEXT NOT NULL CHECK (
    json_valid(expected_effect_json) AND json_type(expected_effect_json) = 'object'
  ),
  expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  UNIQUE (agent_run_id, effect_idempotency_key),
  UNIQUE (
    id, digest, session_id, agent_run_id, action_class,
    provider, operation, exact_target
  ),
  CHECK (expires_at_ms >= created_at_ms),
  FOREIGN KEY (agent_run_id, session_id)
    REFERENCES agent_runs(id, session_id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER action_manifests_immutable_update
BEFORE UPDATE ON action_manifests
BEGIN
  SELECT RAISE(ABORT, 'Action manifests are immutable');
END;

CREATE TRIGGER action_manifests_immutable_delete
BEFORE DELETE ON action_manifests
BEGIN
  SELECT RAISE(ABORT, 'Action manifests are immutable');
END;

CREATE TABLE approval_requests (
  id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  previous_version INTEGER,
  request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
  session_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  run_policy_revision INTEGER NOT NULL CHECK (run_policy_revision >= 1),
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  action_class TEXT NOT NULL CHECK (action_class IN ('scoped-external', 'protected')),
  provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
  operation TEXT NOT NULL CHECK (length(operation) BETWEEN 1 AND 200),
  exact_target TEXT NOT NULL CHECK (length(exact_target) BETWEEN 1 AND 2000),
  subject_kind TEXT NOT NULL CHECK (subject_kind IN ('manifest', 'run-pattern')),
  manifest_id TEXT REFERENCES action_manifests(id) ON DELETE RESTRICT,
  manifest_digest TEXT,
  action_pattern_json TEXT CHECK (
    action_pattern_json IS NULL OR
    (json_valid(action_pattern_json) AND json_type(action_pattern_json) = 'object')
  ),
  action_pattern_digest TEXT,
  subject_digest TEXT NOT NULL CHECK (length(subject_digest) = 64),
  status TEXT NOT NULL CHECK (status IN ('open', 'approved', 'denied', 'expired', 'superseded')),
  expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  resolved_at_ms INTEGER,
  resolved_by_actor_ref TEXT,
  PRIMARY KEY (id, version),
  UNIQUE (id, request_digest),
  UNIQUE (id, version, session_id, agent_run_id),
  UNIQUE (
    id, version, status, session_id, agent_run_id, run_policy_revision,
    runtime_assignment_id, runtime_assignment_generation, sandbox_id,
    sandbox_generation, runtime_principal_id, runtime_authorization_generation,
    action_class, provider, operation, exact_target, subject_kind, subject_digest
  ),
  CHECK (
    (version = 1 AND previous_version IS NULL) OR
    (version > 1 AND previous_version IS NOT NULL AND previous_version = version - 1)
  ),
  CHECK (
    (subject_kind = 'manifest' AND manifest_id IS NOT NULL AND manifest_digest IS NOT NULL
      AND subject_digest = manifest_digest
      AND action_pattern_json IS NULL AND action_pattern_digest IS NULL) OR
    (subject_kind = 'run-pattern' AND manifest_id IS NULL AND manifest_digest IS NULL
      AND action_pattern_json IS NOT NULL AND action_pattern_digest IS NOT NULL
      AND subject_digest = action_pattern_digest)
  ),
  CHECK (subject_kind <> 'run-pattern' OR action_class = 'scoped-external'),
  CHECK (
    subject_kind <> 'run-pattern' OR (
      COALESCE(json_extract(action_pattern_json, '$.actionClass'), '') = action_class
      AND COALESCE(json_extract(action_pattern_json, '$.provider'), '') = provider
      AND COALESCE(json_extract(action_pattern_json, '$.operation'), '') = operation
      AND COALESCE(json_extract(action_pattern_json, '$.targetPattern'), '') = exact_target
      AND COALESCE(json_extract(action_pattern_json, '$.eligibleUse'), '') IN (
        'session_branch_push', 'draft_pull_request_update',
        'ephemeral_preview_update', 'same_credential_nonproduction_target'
      )
      AND COALESCE(json_extract(action_pattern_json, '$.digest'), '') = action_pattern_digest
    )
  ),
  CHECK (expires_at_ms >= created_at_ms),
  CHECK (
    (status = 'open' AND resolved_at_ms IS NULL AND resolved_by_actor_ref IS NULL) OR
    (status IN ('approved', 'denied') AND resolved_at_ms IS NOT NULL
      AND resolved_at_ms <= expires_at_ms AND resolved_by_actor_ref IS NOT NULL) OR
    (status IN ('expired', 'superseded') AND resolved_at_ms IS NOT NULL)
  ),
  CHECK (resolved_at_ms IS NULL OR resolved_at_ms >= created_at_ms),
  CHECK (version <> 1 OR status = 'open'),
  FOREIGN KEY (agent_run_id, session_id)
    REFERENCES agent_runs(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (
    agent_run_id, session_id, run_policy_revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation
  ) REFERENCES run_policy_revisions(
    agent_run_id, session_id, revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation, sandbox_id,
    sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    manifest_id, manifest_digest, session_id, agent_run_id, action_class,
    provider, operation, exact_target
  ) REFERENCES action_manifests(
    id, digest, session_id, agent_run_id, action_class, provider, operation, exact_target
  ) ON DELETE RESTRICT,
  FOREIGN KEY (id, previous_version)
    REFERENCES approval_requests(id, version) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER approval_requests_immutable_update
BEFORE UPDATE ON approval_requests
BEGIN
  SELECT RAISE(ABORT, 'Approval request versions are immutable');
END;

CREATE TRIGGER approval_requests_immutable_delete
BEFORE DELETE ON approval_requests
BEGIN
  SELECT RAISE(ABORT, 'Approval request versions are immutable');
END;

CREATE TRIGGER approval_requests_version_continuity
BEFORE INSERT ON approval_requests
WHEN NEW.previous_version IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM approval_requests previous
  WHERE previous.id = NEW.id
    AND previous.version = NEW.previous_version
    AND previous.session_id = NEW.session_id
    AND previous.agent_run_id = NEW.agent_run_id
    AND previous.run_policy_revision = NEW.run_policy_revision
    AND previous.runtime_assignment_id = NEW.runtime_assignment_id
    AND previous.runtime_assignment_generation = NEW.runtime_assignment_generation
    AND previous.sandbox_id = NEW.sandbox_id
    AND previous.sandbox_generation = NEW.sandbox_generation
    AND previous.runtime_principal_id = NEW.runtime_principal_id
    AND previous.runtime_authorization_generation = NEW.runtime_authorization_generation
    AND previous.action_class = NEW.action_class
    AND previous.provider = NEW.provider
    AND previous.operation = NEW.operation
    AND previous.exact_target = NEW.exact_target
    AND previous.subject_kind = NEW.subject_kind
    AND previous.manifest_id IS NEW.manifest_id
    AND previous.manifest_digest IS NEW.manifest_digest
    AND previous.action_pattern_json IS NEW.action_pattern_json
    AND previous.action_pattern_digest IS NEW.action_pattern_digest
    AND previous.subject_digest = NEW.subject_digest
    AND previous.expires_at_ms = NEW.expires_at_ms
    AND previous.created_at_ms = NEW.created_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'Approval request version changed immutable authority');
END;

CREATE TRIGGER approval_requests_terminal_transition
BEFORE INSERT ON approval_requests
WHEN NEW.previous_version IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM approval_requests previous
  WHERE previous.id = NEW.id
    AND previous.version = NEW.previous_version
    AND previous.status = 'open'
    AND NEW.status IN ('approved', 'denied', 'expired', 'superseded')
)
BEGIN
  SELECT RAISE(ABORT, 'Invalid approval request status transition');
END;

CREATE TRIGGER approval_requests_manifest_expiry
BEFORE INSERT ON approval_requests
WHEN NEW.subject_kind = 'manifest' AND NEW.expires_at_ms > COALESCE(
  (SELECT manifest.expires_at_ms
   FROM action_manifests manifest
   WHERE manifest.id = NEW.manifest_id AND manifest.digest = NEW.manifest_digest),
  -1
)
BEGIN
  SELECT RAISE(ABORT, 'Approval request cannot outlive its action manifest');
END;

CREATE UNIQUE INDEX one_open_approval_request_version
  ON approval_requests(id) WHERE status = 'open';

CREATE TABLE attention_requests (
  id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  previous_version INTEGER,
  session_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  run_policy_revision INTEGER NOT NULL CHECK (run_policy_revision >= 1),
  reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 1000),
  proposal_kind TEXT NOT NULL CHECK (proposal_kind IN ('action-manifest', 'structured-decision')),
  proposal_ref TEXT NOT NULL CHECK (length(proposal_ref) BETWEEN 1 AND 1000),
  proposal_digest TEXT NOT NULL CHECK (length(proposal_digest) = 64),
  risk TEXT NOT NULL CHECK (length(risk) BETWEEN 1 AND 2000),
  eligible_responder_capabilities_json TEXT NOT NULL CHECK (
    json_valid(eligible_responder_capabilities_json)
    AND json_type(eligible_responder_capabilities_json) = 'array'
  ),
  valid_resolutions_json TEXT NOT NULL CHECK (
    json_valid(valid_resolutions_json) AND json_type(valid_resolutions_json) = 'array'
  ),
  deadline_at_ms INTEGER NOT NULL CHECK (deadline_at_ms >= 0),
  status TEXT NOT NULL CHECK (status IN ('open', 'resolved', 'superseded', 'timed-out')),
  linked_approval_request_id TEXT,
  linked_approval_request_version INTEGER,
  independent_work_may_continue INTEGER NOT NULL CHECK (independent_work_may_continue IN (0, 1)),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  resolved_at_ms INTEGER,
  PRIMARY KEY (id, version),
  UNIQUE (id, proposal_digest, version),
  CHECK (
    (version = 1 AND previous_version IS NULL) OR
    (version > 1 AND previous_version IS NOT NULL AND previous_version = version - 1)
  ),
  CHECK (
    (status = 'open' AND resolved_at_ms IS NULL) OR
    (status <> 'open' AND resolved_at_ms IS NOT NULL)
  ),
  CHECK (deadline_at_ms >= created_at_ms),
  CHECK (resolved_at_ms IS NULL OR resolved_at_ms >= created_at_ms),
  CHECK (
    (linked_approval_request_id IS NULL AND linked_approval_request_version IS NULL) OR
    (linked_approval_request_id IS NOT NULL AND linked_approval_request_version IS NOT NULL)
  ),
  FOREIGN KEY (agent_run_id, session_id)
    REFERENCES agent_runs(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (agent_run_id, run_policy_revision)
    REFERENCES run_policy_revisions(agent_run_id, revision) ON DELETE RESTRICT,
  FOREIGN KEY (
    linked_approval_request_id, linked_approval_request_version, session_id, agent_run_id
  ) REFERENCES approval_requests(id, version, session_id, agent_run_id) ON DELETE RESTRICT,
  FOREIGN KEY (id, previous_version)
    REFERENCES attention_requests(id, version) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER attention_requests_immutable_update
BEFORE UPDATE ON attention_requests
BEGIN
  SELECT RAISE(ABORT, 'Attention request versions are immutable');
END;

CREATE TRIGGER attention_requests_immutable_delete
BEFORE DELETE ON attention_requests
BEGIN
  SELECT RAISE(ABORT, 'Attention request versions are immutable');
END;

CREATE TRIGGER attention_requests_version_continuity
BEFORE INSERT ON attention_requests
WHEN NEW.previous_version IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM attention_requests previous
  WHERE previous.id = NEW.id
    AND previous.version = NEW.previous_version
    AND previous.session_id = NEW.session_id
    AND previous.agent_run_id = NEW.agent_run_id
    AND previous.run_policy_revision = NEW.run_policy_revision
    AND previous.reason = NEW.reason
    AND previous.proposal_kind = NEW.proposal_kind
    AND previous.proposal_ref = NEW.proposal_ref
    AND previous.proposal_digest = NEW.proposal_digest
    AND previous.risk = NEW.risk
    AND previous.eligible_responder_capabilities_json =
      NEW.eligible_responder_capabilities_json
    AND previous.valid_resolutions_json = NEW.valid_resolutions_json
    AND previous.deadline_at_ms = NEW.deadline_at_ms
    AND previous.linked_approval_request_id IS NEW.linked_approval_request_id
    AND previous.linked_approval_request_version IS NEW.linked_approval_request_version
    AND previous.independent_work_may_continue = NEW.independent_work_may_continue
    AND previous.created_at_ms = NEW.created_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'Attention request version changed immutable proposal');
END;

CREATE TRIGGER attention_requests_valid_transition
BEFORE INSERT ON attention_requests
WHEN (
  NEW.version = 1 AND NEW.status <> 'open'
) OR (
  NEW.version > 1 AND NOT EXISTS (
    SELECT 1
    FROM attention_requests previous
    WHERE previous.id = NEW.id
      AND previous.version = NEW.previous_version
      AND previous.status = 'open'
      AND NEW.status IN ('resolved', 'superseded', 'timed-out')
  )
)
BEGIN
  SELECT RAISE(ABORT, 'Invalid attention request status transition');
END;

CREATE TRIGGER attention_requests_manifest_binding
BEFORE INSERT ON attention_requests
WHEN NEW.proposal_kind = 'action-manifest' AND NOT EXISTS (
  SELECT 1
  FROM action_manifests manifest
  WHERE manifest.id = NEW.proposal_ref
    AND manifest.digest = NEW.proposal_digest
    AND manifest.session_id = NEW.session_id
    AND manifest.agent_run_id = NEW.agent_run_id
)
BEGIN
  SELECT RAISE(ABORT, 'Attention request does not match its action manifest');
END;

CREATE TRIGGER attention_requests_approval_binding
BEFORE INSERT ON attention_requests
WHEN NEW.linked_approval_request_id IS NOT NULL AND (
  NEW.proposal_kind <> 'action-manifest' OR NOT EXISTS (
    SELECT 1
    FROM approval_requests approval
    WHERE approval.id = NEW.linked_approval_request_id
      AND approval.version = NEW.linked_approval_request_version
      AND approval.session_id = NEW.session_id
      AND approval.agent_run_id = NEW.agent_run_id
      AND approval.run_policy_revision = NEW.run_policy_revision
      AND approval.subject_kind = 'manifest'
      AND approval.manifest_id = NEW.proposal_ref
      AND approval.manifest_digest = NEW.proposal_digest
  )
)
BEGIN
  SELECT RAISE(ABORT, 'Attention request approval does not match its exact proposal');
END;

CREATE UNIQUE INDEX one_open_attention_request_version
  ON attention_requests(id) WHERE status = 'open';

CREATE TABLE action_grants (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  run_policy_revision INTEGER NOT NULL CHECK (run_policy_revision >= 1),
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  approval_request_id TEXT NOT NULL,
  approval_request_version INTEGER NOT NULL CHECK (approval_request_version >= 1),
  approval_status TEXT NOT NULL CHECK (approval_status = 'approved'),
  approval_subject_kind TEXT NOT NULL CHECK (
    approval_subject_kind IN ('manifest', 'run-pattern')
  ),
  action_class TEXT NOT NULL CHECK (action_class IN ('scoped-external', 'protected')),
  provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 200),
  operation TEXT NOT NULL CHECK (length(operation) BETWEEN 1 AND 200),
  target TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 2000),
  credential_ref TEXT,
  budget_json TEXT NOT NULL CHECK (
    json_valid(budget_json) AND json_type(budget_json) = 'object'
  ),
  usage_ledger_ref TEXT NOT NULL CHECK (length(usage_ledger_ref) BETWEEN 1 AND 500),
  scope_kind TEXT NOT NULL CHECK (scope_kind IN ('once', 'run')),
  scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 64),
  manifest_digest TEXT CHECK (manifest_digest IS NULL OR length(manifest_digest) = 64),
  effect_idempotency_key TEXT,
  action_pattern_json TEXT CHECK (
    action_pattern_json IS NULL OR
    (json_valid(action_pattern_json) AND json_type(action_pattern_json) = 'object')
  ),
  action_pattern_digest TEXT CHECK (
    action_pattern_digest IS NULL OR length(action_pattern_digest) = 64
  ),
  eligible_run_use TEXT CHECK (eligible_run_use IS NULL OR eligible_run_use IN (
    'session_branch_push', 'draft_pull_request_update',
    'ephemeral_preview_update', 'same_credential_nonproduction_target'
  )),
  issuer_actor_ref TEXT NOT NULL CHECK (length(issuer_actor_ref) BETWEEN 1 AND 300),
  issuer_approval_authority_revision TEXT NOT NULL
    CHECK (length(issuer_approval_authority_revision) BETWEEN 1 AND 300),
  expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
  signature TEXT NOT NULL CHECK (length(signature) BETWEEN 1 AND 4000),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  UNIQUE (approval_request_id, approval_request_version),
  CHECK (
    (scope_kind = 'once' AND approval_subject_kind = 'manifest'
      AND manifest_digest IS NOT NULL AND scope_digest = manifest_digest
      AND effect_idempotency_key IS NOT NULL
      AND action_pattern_json IS NULL AND action_pattern_digest IS NULL
      AND eligible_run_use IS NULL) OR
    (scope_kind = 'run' AND manifest_digest IS NULL AND effect_idempotency_key IS NULL
      AND approval_subject_kind = 'run-pattern'
      AND action_pattern_json IS NOT NULL AND action_pattern_digest IS NOT NULL
      AND scope_digest = action_pattern_digest AND eligible_run_use IS NOT NULL
      AND COALESCE(json_extract(action_pattern_json, '$.actionClass'), '') = action_class
      AND COALESCE(json_extract(action_pattern_json, '$.provider'), '') = provider
      AND COALESCE(json_extract(action_pattern_json, '$.operation'), '') = operation
      AND COALESCE(json_extract(action_pattern_json, '$.targetPattern'), '') = target
      AND COALESCE(json_extract(action_pattern_json, '$.eligibleUse'), '') = eligible_run_use
      AND COALESCE(json_extract(action_pattern_json, '$.digest'), '') = action_pattern_digest
      AND credential_ref IS json_extract(action_pattern_json, '$.credentialRef'))
  ),
  CHECK (scope_kind <> 'run' OR action_class = 'scoped-external'),
  CHECK (expires_at_ms >= created_at_ms),
  FOREIGN KEY (agent_run_id, session_id)
    REFERENCES agent_runs(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (
    agent_run_id, session_id, run_policy_revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation
  ) REFERENCES run_policy_revisions(
    agent_run_id, session_id, revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation, sandbox_id,
    sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    approval_request_id, approval_request_version, approval_status,
    session_id, agent_run_id, run_policy_revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation, action_class,
    provider, operation, target, approval_subject_kind, scope_digest
  ) REFERENCES approval_requests(
    id, version, status, session_id, agent_run_id, run_policy_revision,
    runtime_assignment_id, runtime_assignment_generation, sandbox_id,
    sandbox_generation, runtime_principal_id, runtime_authorization_generation,
    action_class, provider, operation, exact_target, subject_kind, subject_digest
  ) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER action_grants_expiry_within_approval
BEFORE INSERT ON action_grants
WHEN NOT EXISTS (
  SELECT 1
  FROM approval_requests approval
  WHERE approval.id = NEW.approval_request_id
    AND approval.version = NEW.approval_request_version
    AND approval.status = 'approved'
    AND approval.resolved_at_ms IS NOT NULL
    AND approval.resolved_at_ms <= NEW.created_at_ms
    AND NEW.expires_at_ms <= approval.expires_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'Action grant is outside its approved request window');
END;

CREATE TRIGGER action_grants_once_manifest_binding
BEFORE INSERT ON action_grants
WHEN NEW.scope_kind = 'once' AND NOT EXISTS (
  SELECT 1
  FROM action_manifests manifest
  WHERE manifest.digest = NEW.manifest_digest
    AND manifest.session_id = NEW.session_id
    AND manifest.agent_run_id = NEW.agent_run_id
    AND manifest.action_class = NEW.action_class
    AND manifest.provider = NEW.provider
    AND manifest.operation = NEW.operation
    AND manifest.exact_target = NEW.target
    AND manifest.effect_idempotency_key = NEW.effect_idempotency_key
    AND manifest.credential_ref IS NEW.credential_ref
    AND manifest.expires_at_ms >= NEW.expires_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'One-shot grant does not match its immutable action manifest');
END;

CREATE TRIGGER action_grants_run_pattern_binding
BEFORE INSERT ON action_grants
WHEN NEW.scope_kind = 'run' AND NOT EXISTS (
  SELECT 1
  FROM approval_requests approval
  WHERE approval.id = NEW.approval_request_id
    AND approval.version = NEW.approval_request_version
    AND approval.status = 'approved'
    AND approval.subject_kind = 'run-pattern'
    AND approval.action_pattern_digest = NEW.action_pattern_digest
    AND approval.action_pattern_json = NEW.action_pattern_json
)
BEGIN
  SELECT RAISE(ABORT, 'Run grant does not match its approved action pattern');
END;

CREATE TRIGGER action_grants_immutable_update
BEFORE UPDATE ON action_grants
BEGIN
  SELECT RAISE(ABORT, 'Action grants are immutable');
END;

CREATE TRIGGER action_grants_immutable_delete
BEFORE DELETE ON action_grants
BEGIN
  SELECT RAISE(ABORT, 'Action grants are immutable');
END;

CREATE INDEX action_grants_by_run_expiry
  ON action_grants(agent_run_id, expires_at_ms);

CREATE TABLE action_grant_states (
  grant_id TEXT NOT NULL REFERENCES action_grants(id) ON DELETE RESTRICT,
  version INTEGER NOT NULL CHECK (version >= 1),
  previous_version INTEGER,
  status TEXT NOT NULL CHECK (status IN (
    'issued', 'enforcement-pending', 'active', 'consumed', 'expired',
    'revoked', 'invalidated', 'enforcement-failed'
  )),
  reason TEXT NOT NULL CHECK (reason IN (
    'issued', 'enforcement', 'consumed', 'expired', 'explicit-revocation',
    'policy-revision', 'runtime-assignment', 'sandbox-generation',
    'runtime-authorization', 'run-terminal', 'enforcement-failed'
  )),
  actor_ref TEXT NOT NULL CHECK (length(actor_ref) BETWEEN 1 AND 300),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  PRIMARY KEY (grant_id, version),
  CHECK (
    (version = 1 AND previous_version IS NULL) OR
    (version > 1 AND previous_version IS NOT NULL AND previous_version = version - 1)
  ),
  CHECK (
    (status = 'issued' AND reason = 'issued') OR
    (status IN ('enforcement-pending', 'active') AND reason = 'enforcement') OR
    (status = 'consumed' AND reason = 'consumed') OR
    (status = 'expired' AND reason = 'expired') OR
    (status = 'revoked' AND reason = 'explicit-revocation') OR
    (status = 'invalidated' AND reason IN (
      'policy-revision', 'runtime-assignment', 'sandbox-generation',
      'runtime-authorization', 'run-terminal'
    )) OR
    (status = 'enforcement-failed' AND reason = 'enforcement-failed')
  ),
  FOREIGN KEY (grant_id, previous_version)
    REFERENCES action_grant_states(grant_id, version) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER action_grant_states_immutable_update
BEFORE UPDATE ON action_grant_states
BEGIN
  SELECT RAISE(ABORT, 'Action grant state versions are immutable');
END;

CREATE TRIGGER action_grant_states_immutable_delete
BEFORE DELETE ON action_grant_states
BEGIN
  SELECT RAISE(ABORT, 'Action grant state versions are immutable');
END;

CREATE TRIGGER action_grant_states_valid_transition
BEFORE INSERT ON action_grant_states
WHEN (
  NEW.version = 1 AND (NEW.status <> 'issued' OR NEW.reason <> 'issued')
) OR (
  NEW.version > 1 AND NOT EXISTS (
    SELECT 1
    FROM action_grant_states previous
    WHERE previous.grant_id = NEW.grant_id
      AND previous.version = NEW.previous_version
      AND previous.created_at_ms <= NEW.created_at_ms
      AND (
        (previous.status = 'issued' AND NEW.status IN (
          'enforcement-pending', 'active', 'consumed', 'expired',
          'revoked', 'invalidated', 'enforcement-failed'
        )) OR
        (previous.status = 'enforcement-pending' AND NEW.status IN (
          'active', 'consumed', 'expired', 'revoked', 'invalidated', 'enforcement-failed'
        )) OR
        (previous.status = 'active' AND NEW.status IN (
          'consumed', 'expired', 'revoked', 'invalidated', 'enforcement-failed'
        ))
      )
  )
)
BEGIN
  SELECT RAISE(ABORT, 'Invalid action grant state transition');
END;

CREATE INDEX action_grant_states_by_status
  ON action_grant_states(status, created_at_ms);

CREATE TABLE grant_reviews (
  id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  previous_version INTEGER,
  session_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  reason TEXT NOT NULL CHECK (reason IN (
    'policy-revision', 'runtime-assignment', 'sandbox-generation',
    'runtime-authorization', 'credential', 'explicit-revocation', 'recovery'
  )),
  safe_default TEXT NOT NULL CHECK (safe_default = 'revoke-all'),
  status TEXT NOT NULL CHECK (status IN ('open', 'resolved', 'superseded')),
  stale_grant_ids_json TEXT NOT NULL CHECK (
    json_valid(stale_grant_ids_json) AND json_type(stale_grant_ids_json) = 'array'
  ),
  intentionally_revoked_grant_ids_json TEXT NOT NULL CHECK (
    json_valid(intentionally_revoked_grant_ids_json)
    AND json_type(intentionally_revoked_grant_ids_json) = 'array'
  ),
  reissuable_candidate_grant_ids_json TEXT NOT NULL CHECK (
    json_valid(reissuable_candidate_grant_ids_json)
    AND json_type(reissuable_candidate_grant_ids_json) = 'array'
  ),
  target_run_policy_revision INTEGER NOT NULL CHECK (target_run_policy_revision >= 1),
  target_runtime_assignment_id TEXT NOT NULL,
  target_runtime_assignment_generation INTEGER NOT NULL
    CHECK (target_runtime_assignment_generation >= 1),
  target_sandbox_id TEXT NOT NULL,
  target_sandbox_generation INTEGER NOT NULL CHECK (target_sandbox_generation >= 1),
  target_runtime_principal_id TEXT NOT NULL,
  target_runtime_authorization_generation INTEGER NOT NULL
    CHECK (target_runtime_authorization_generation >= 1),
  resolution_kind TEXT CHECK (resolution_kind IS NULL OR resolution_kind IN (
    'revoke-all', 'reissue-selected'
  )),
  selected_candidate_grant_ids_json TEXT CHECK (
    selected_candidate_grant_ids_json IS NULL OR
    (json_valid(selected_candidate_grant_ids_json)
      AND json_type(selected_candidate_grant_ids_json) = 'array')
  ),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  resolved_at_ms INTEGER,
  resolved_by_actor_ref TEXT,
  PRIMARY KEY (id, version),
  CHECK (
    (version = 1 AND previous_version IS NULL) OR
    (version > 1 AND previous_version IS NOT NULL AND previous_version = version - 1)
  ),
  CHECK (
    (status = 'open' AND resolution_kind IS NULL
      AND selected_candidate_grant_ids_json IS NULL
      AND resolved_at_ms IS NULL AND resolved_by_actor_ref IS NULL) OR
    (status = 'resolved' AND resolution_kind IS NOT NULL
      AND resolved_at_ms IS NOT NULL AND resolved_by_actor_ref IS NOT NULL) OR
    (status = 'superseded' AND resolution_kind IS NULL
      AND selected_candidate_grant_ids_json IS NULL AND resolved_at_ms IS NOT NULL)
  ),
  CHECK (
    resolution_kind <> 'reissue-selected' OR selected_candidate_grant_ids_json IS NOT NULL
  ),
  CHECK (
    resolution_kind <> 'revoke-all' OR selected_candidate_grant_ids_json IS NULL
  ),
  CHECK (resolved_at_ms IS NULL OR resolved_at_ms >= created_at_ms),
  FOREIGN KEY (agent_run_id, session_id)
    REFERENCES agent_runs(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (
    agent_run_id, session_id, target_run_policy_revision,
    target_runtime_assignment_id, target_runtime_assignment_generation,
    target_sandbox_id, target_sandbox_generation, target_runtime_principal_id,
    target_runtime_authorization_generation
  ) REFERENCES run_policy_revisions(
    agent_run_id, session_id, revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    target_runtime_assignment_id, session_id, target_runtime_assignment_generation,
    target_sandbox_id, target_sandbox_generation, target_runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (id, previous_version)
    REFERENCES grant_reviews(id, version) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER grant_reviews_immutable_update
BEFORE UPDATE ON grant_reviews
BEGIN
  SELECT RAISE(ABORT, 'Grant review versions are immutable');
END;

CREATE TRIGGER grant_reviews_immutable_delete
BEFORE DELETE ON grant_reviews
BEGIN
  SELECT RAISE(ABORT, 'Grant review versions are immutable');
END;

CREATE TRIGGER grant_reviews_valid_grant_sets
BEFORE INSERT ON grant_reviews
WHEN
  EXISTS (
    SELECT 1 FROM json_each(NEW.stale_grant_ids_json) entry
    WHERE entry.type <> 'text'
  ) OR
  EXISTS (
    SELECT 1 FROM json_each(NEW.intentionally_revoked_grant_ids_json) entry
    WHERE entry.type <> 'text'
  ) OR
  EXISTS (
    SELECT 1 FROM json_each(NEW.reissuable_candidate_grant_ids_json) entry
    WHERE entry.type <> 'text'
  ) OR
  (
    NEW.selected_candidate_grant_ids_json IS NOT NULL AND EXISTS (
      SELECT 1 FROM json_each(NEW.selected_candidate_grant_ids_json) entry
      WHERE entry.type <> 'text'
    )
  ) OR
  (SELECT COUNT(*) FROM json_each(NEW.stale_grant_ids_json)) <>
    (SELECT COUNT(DISTINCT value) FROM json_each(NEW.stale_grant_ids_json)) OR
  (SELECT COUNT(*) FROM json_each(NEW.intentionally_revoked_grant_ids_json)) <>
    (SELECT COUNT(DISTINCT value) FROM json_each(NEW.intentionally_revoked_grant_ids_json)) OR
  (SELECT COUNT(*) FROM json_each(NEW.reissuable_candidate_grant_ids_json)) <>
    (SELECT COUNT(DISTINCT value) FROM json_each(NEW.reissuable_candidate_grant_ids_json)) OR
  (
    NEW.selected_candidate_grant_ids_json IS NOT NULL AND
    (SELECT COUNT(*) FROM json_each(NEW.selected_candidate_grant_ids_json)) <>
      (SELECT COUNT(DISTINCT value) FROM json_each(NEW.selected_candidate_grant_ids_json))
  ) OR
  EXISTS (
    SELECT 1
    FROM json_each(NEW.stale_grant_ids_json) entry
    LEFT JOIN action_grants grant_row
      ON grant_row.id = entry.value
     AND grant_row.session_id = NEW.session_id
     AND grant_row.agent_run_id = NEW.agent_run_id
    WHERE grant_row.id IS NULL
  ) OR
  EXISTS (
    SELECT 1
    FROM json_each(NEW.intentionally_revoked_grant_ids_json) entry
    WHERE NOT EXISTS (
      SELECT 1 FROM json_each(NEW.stale_grant_ids_json) stale
      WHERE stale.value = entry.value
    )
  ) OR
  EXISTS (
    SELECT 1
    FROM json_each(NEW.reissuable_candidate_grant_ids_json) entry
    WHERE NOT EXISTS (
      SELECT 1 FROM json_each(NEW.stale_grant_ids_json) stale
      WHERE stale.value = entry.value
    )
  ) OR
  EXISTS (
    SELECT 1
    FROM json_each(NEW.intentionally_revoked_grant_ids_json) revoked
    JOIN json_each(NEW.reissuable_candidate_grant_ids_json) candidate
      ON candidate.value = revoked.value
  ) OR
  (
    NEW.selected_candidate_grant_ids_json IS NOT NULL AND EXISTS (
      SELECT 1
      FROM json_each(NEW.selected_candidate_grant_ids_json) selected
      WHERE NOT EXISTS (
        SELECT 1 FROM json_each(NEW.reissuable_candidate_grant_ids_json) candidate
        WHERE candidate.value = selected.value
      )
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'Grant review contains invalid or unrelated grant ids');
END;

CREATE TRIGGER grant_reviews_version_continuity
BEFORE INSERT ON grant_reviews
WHEN NEW.previous_version IS NOT NULL AND NOT EXISTS (
  SELECT 1
  FROM grant_reviews previous
  WHERE previous.id = NEW.id
    AND previous.version = NEW.previous_version
    AND previous.session_id = NEW.session_id
    AND previous.agent_run_id = NEW.agent_run_id
    AND previous.reason = NEW.reason
    AND previous.safe_default = NEW.safe_default
    AND previous.stale_grant_ids_json = NEW.stale_grant_ids_json
    AND previous.intentionally_revoked_grant_ids_json =
      NEW.intentionally_revoked_grant_ids_json
    AND previous.reissuable_candidate_grant_ids_json =
      NEW.reissuable_candidate_grant_ids_json
    AND previous.target_run_policy_revision = NEW.target_run_policy_revision
    AND previous.target_runtime_assignment_id = NEW.target_runtime_assignment_id
    AND previous.target_runtime_assignment_generation =
      NEW.target_runtime_assignment_generation
    AND previous.target_sandbox_id = NEW.target_sandbox_id
    AND previous.target_sandbox_generation = NEW.target_sandbox_generation
    AND previous.target_runtime_principal_id = NEW.target_runtime_principal_id
    AND previous.target_runtime_authorization_generation =
      NEW.target_runtime_authorization_generation
    AND previous.created_at_ms = NEW.created_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'Grant review version changed immutable review scope');
END;

CREATE TRIGGER grant_reviews_valid_transition
BEFORE INSERT ON grant_reviews
WHEN (
  NEW.version = 1 AND NEW.status <> 'open'
) OR (
  NEW.version > 1 AND NOT EXISTS (
    SELECT 1
    FROM grant_reviews previous
    WHERE previous.id = NEW.id
      AND previous.version = NEW.previous_version
      AND previous.status = 'open'
      AND NEW.status IN ('resolved', 'superseded')
  )
)
BEGIN
  SELECT RAISE(ABORT, 'Invalid grant review status transition');
END;

CREATE UNIQUE INDEX one_open_grant_review_version
  ON grant_reviews(id) WHERE status = 'open';
`;

const RUNTIME_RUN_COMMAND_SCHEMA = `
CREATE TABLE runtime_run_commands (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  command_sequence INTEGER NOT NULL CHECK (command_sequence >= 1),
  previous_command_sequence INTEGER,
  operation TEXT NOT NULL CHECK (operation IN ('run.pause', 'run.resume', 'run.stop')),
  target_lifecycle TEXT NOT NULL CHECK (target_lifecycle IN ('active', 'paused', 'stopped')),
  expected_run_state_version INTEGER NOT NULL CHECK (expected_run_state_version >= 1),
  target_run_state_version INTEGER NOT NULL CHECK (
    target_run_state_version = expected_run_state_version + 1
  ),
  run_policy_revision INTEGER NOT NULL CHECK (run_policy_revision >= 1),
  goal_set_id TEXT NOT NULL CHECK (length(goal_set_id) BETWEEN 1 AND 300),
  goal_set_revision INTEGER NOT NULL CHECK (goal_set_revision >= 1),
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  source_session_sequence INTEGER NOT NULL CHECK (source_session_sequence >= 1),
  command_json TEXT NOT NULL CHECK (
    json_valid(command_json) AND json_type(command_json) = 'object'
    AND COALESCE(
        json_extract(command_json, '$.commandId') = id
        AND json_extract(command_json, '$.kind') = operation
        AND json_extract(command_json, '$.agentRunId') = agent_run_id
        AND json_extract(command_json, '$.runPolicyRevision') = run_policy_revision
        AND json_type(command_json, '$.projectCeilingRevision') = 'text'
        AND length(json_extract(command_json, '$.projectCeilingRevision')) BETWEEN 1 AND 300
        AND json_extract(
          command_json, '$.fromRunStateVersion'
        ) = expected_run_state_version
        AND json_extract(
          command_json, '$.toRunStateVersion'
        ) = target_run_state_version
        AND json_extract(
          command_json, '$.runtimeAuthorizationGeneration'
        ) = runtime_authorization_generation
        AND json_type(command_json, '$.causationId') = 'text'
        AND length(json_extract(command_json, '$.causationId')) BETWEEN 1 AND 300
        AND json_type(command_json, '$.actor') = 'object'
        AND COALESCE(json_extract(command_json, '$.actor.kind'), '') IN ('human', 'system')
        AND json_type(command_json, '$.actor.actorRef') = 'text'
        AND length(json_extract(command_json, '$.actor.actorRef')) BETWEEN 1 AND 300
        AND json_extract(command_json, '$.issuedAtMs') = created_at_ms
        AND json_extract(command_json, '$.deadlineAtMs') = deadline_at_ms
        AND json_extract(command_json, '$.authority.issuer') = 'team-session'
        AND json_type(command_json, '$.authority.issuerKeyId') = 'text'
        AND length(json_extract(command_json, '$.authority.issuerKeyId')) BETWEEN 1 AND 300
        AND json_extract(command_json, '$.authority.audience') = 'runtime'
        AND json_extract(command_json, '$.authority.capability') = operation
        AND json_extract(command_json, '$.authority.claimsDigest') = authority_digest
        AND json_type(command_json, '$.authority.issuedAtMs') = 'integer'
        AND json_extract(command_json, '$.authority.issuedAtMs') >= 0
        AND json_extract(command_json, '$.authority.issuedAtMs') <= created_at_ms
        AND json_type(command_json, '$.authority.expiresAtMs') = 'integer'
        AND json_extract(command_json, '$.authority.expiresAtMs') > created_at_ms
        AND json_type(command_json, '$.authority.signature') = 'text'
        AND length(json_extract(command_json, '$.authority.signature')) BETWEEN 1 AND 4000
        AND json_extract(command_json, '$.binding.sessionId') = session_id
        AND json_extract(
          command_json, '$.binding.runtimeAssignmentId'
        ) = runtime_assignment_id
        AND json_extract(
          command_json, '$.binding.runtimeAssignmentGeneration'
        ) = runtime_assignment_generation
        AND json_extract(command_json, '$.binding.sandboxId') = sandbox_id
        AND json_extract(
          command_json, '$.binding.sandboxGeneration'
        ) = sandbox_generation
        AND json_extract(
          command_json, '$.binding.runtimePrincipalId'
        ) = runtime_principal_id,
      0
    )
    AND COALESCE((
      (operation = 'run.pause'
        AND COALESCE(json_extract(command_json, '$.reason'), '') IN (
          'human', 'attention_timeout', 'limit', 'safety'
        )) OR
      (operation = 'run.resume'
        AND json_type(command_json, '$.accountableAssigneePresent') = 'true'
        AND json_extract(command_json, '$.accountableAssigneePresent') = 1) OR
      (operation = 'run.stop'
        AND COALESCE(json_extract(command_json, '$.reason'), '') IN (
          'human', 'final_review_closed', 'superseded'
        ))
    ), 0)
  ),
  command_digest TEXT NOT NULL CHECK (
    length(command_digest) = 64 AND command_digest NOT GLOB '*[^0-9a-f]*'
  ),
  authority_digest TEXT NOT NULL CHECK (
    length(authority_digest) = 64 AND authority_digest NOT GLOB '*[^0-9a-f]*'
  ),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  deadline_at_ms INTEGER NOT NULL CHECK (deadline_at_ms > created_at_ms),
  UNIQUE (agent_run_id, command_sequence),
  UNIQUE (id, agent_run_id),
  UNIQUE (
    id, session_id, agent_run_id, command_sequence,
    expected_run_state_version, target_run_state_version, source_session_sequence
  ),
  UNIQUE (
    id, session_id, agent_run_id, command_sequence, run_policy_revision,
    goal_set_id, goal_set_revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation,
    expected_run_state_version, target_run_state_version,
    source_session_sequence, command_digest
  ),
  CHECK (
    (command_sequence = 1 AND previous_command_sequence IS NULL) OR
    (command_sequence > 1 AND previous_command_sequence = command_sequence - 1)
  ),
  CHECK (
    (operation = 'run.resume' AND target_lifecycle = 'active') OR
    (operation = 'run.pause' AND target_lifecycle = 'paused') OR
    (operation = 'run.stop' AND target_lifecycle = 'stopped')
  ),
  FOREIGN KEY (session_id, source_session_sequence)
    REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
  FOREIGN KEY (agent_run_id, session_id)
    REFERENCES agent_runs(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (agent_run_id, goal_set_id, goal_set_revision)
    REFERENCES goal_sets(agent_run_id, goal_set_id, revision) ON DELETE RESTRICT,
  FOREIGN KEY (
    agent_run_id, session_id, run_policy_revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation
  ) REFERENCES run_policy_revisions(
    agent_run_id, session_id, revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    session_id, runtime_authorization_generation, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_authorization_epochs(
    session_id, generation, runtime_assignment_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (agent_run_id, previous_command_sequence)
    REFERENCES runtime_run_commands(agent_run_id, command_sequence) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER runtime_run_commands_immutable_update
BEFORE UPDATE ON runtime_run_commands
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run commands are immutable');
END;

CREATE TRIGGER runtime_run_commands_json_scope_binding
BEFORE INSERT ON runtime_run_commands
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_assignments assignment
  WHERE assignment.id = NEW.runtime_assignment_id
    AND assignment.session_id = NEW.session_id
    AND assignment.generation = NEW.runtime_assignment_generation
    AND assignment.sandbox_id = NEW.sandbox_id
    AND assignment.sandbox_generation = NEW.sandbox_generation
    AND assignment.runtime_principal_id = NEW.runtime_principal_id
    AND json_extract(NEW.command_json, '$.binding.teamId') = assignment.team_id
    AND json_extract(NEW.command_json, '$.binding.projectId') = assignment.project_id
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command JSON scope does not match its binding');
END;

CREATE TRIGGER runtime_run_commands_source_event_binding
BEFORE INSERT ON runtime_run_commands
WHEN NOT EXISTS (
  SELECT 1
  FROM session_events event
  JOIN run_policy_revisions policy
    ON policy.agent_run_id = NEW.agent_run_id
   AND policy.session_id = NEW.session_id
   AND policy.revision = NEW.run_policy_revision
  WHERE event.session_id = NEW.session_id
    AND event.sequence = NEW.source_session_sequence
    AND event.type = 'run.runtime-command.requested'
    AND json_extract(event.payload_json, '$.commandId') = NEW.id
    AND json_extract(event.payload_json, '$.agentRunId') = NEW.agent_run_id
    AND json_extract(NEW.command_json, '$.causationId') = event.event_id
    AND json_extract(NEW.command_json, '$.actor.kind') = event.actor_kind
    AND json_extract(NEW.command_json, '$.actor.actorRef') = event.actor_user_id
    AND json_extract(
      NEW.command_json, '$.projectCeilingRevision'
    ) = policy.project_ceiling_revision
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command source event does not match');
END;

CREATE TRIGGER runtime_run_commands_immutable_delete
BEFORE DELETE ON runtime_run_commands
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run commands are immutable');
END;

CREATE TABLE runtime_run_command_dispatch (
  command_id TEXT PRIMARY KEY,
  agent_run_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'pending', 'processing', 'awaiting-receipt',
    'enforced', 'rejected', 'quarantined', 'superseded', 'failed'
  )),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  lease_owner TEXT,
  lease_expires_at_ms INTEGER,
  last_safe_error_code TEXT CHECK (
    last_safe_error_code IS NULL OR length(last_safe_error_code) BETWEEN 1 AND 200
  ),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
  terminal_at_ms INTEGER,
  CHECK (
    (status = 'processing' AND lease_owner IS NOT NULL AND lease_expires_at_ms IS NOT NULL) OR
    (status <> 'processing' AND lease_owner IS NULL AND lease_expires_at_ms IS NULL)
  ),
  CHECK (
    (status IN ('enforced', 'rejected', 'quarantined', 'superseded', 'failed')
      AND terminal_at_ms IS NOT NULL AND terminal_at_ms >= created_at_ms) OR
    (status IN ('pending', 'processing', 'awaiting-receipt') AND terminal_at_ms IS NULL)
  ),
  FOREIGN KEY (command_id, agent_run_id)
    REFERENCES runtime_run_commands(id, agent_run_id) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX one_unresolved_runtime_run_command_per_run
  ON runtime_run_command_dispatch(agent_run_id)
  WHERE status IN ('pending', 'processing', 'awaiting-receipt');

CREATE TRIGGER runtime_run_command_dispatch_identity_immutable
BEFORE UPDATE OF command_id, agent_run_id, created_at_ms ON runtime_run_command_dispatch
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command dispatch identity is immutable');
END;

CREATE TRIGGER runtime_run_command_dispatch_initial_state
BEFORE INSERT ON runtime_run_command_dispatch
WHEN NEW.status <> 'pending' OR NEW.attempts <> 0 OR
  NEW.lease_owner IS NOT NULL OR NEW.lease_expires_at_ms IS NOT NULL OR
  NEW.last_safe_error_code IS NOT NULL OR NEW.terminal_at_ms IS NOT NULL OR
  NEW.updated_at_ms <> NEW.created_at_ms
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command dispatch must begin pending');
END;

CREATE TRIGGER runtime_run_command_dispatch_immutable_delete
BEFORE DELETE ON runtime_run_command_dispatch
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command dispatch cannot be deleted');
END;

CREATE TRIGGER runtime_run_command_dispatch_valid_transition
BEFORE UPDATE ON runtime_run_command_dispatch
WHEN
  OLD.status IN ('enforced', 'rejected', 'quarantined', 'superseded', 'failed') OR
  NEW.updated_at_ms < OLD.updated_at_ms OR
  NEW.attempts < OLD.attempts OR
  NEW.attempts > OLD.attempts + 1 OR
  (NEW.attempts = OLD.attempts + 1 AND NOT (
    NEW.status = 'processing' AND OLD.status IN ('pending', 'awaiting-receipt')
  )) OR
  (NEW.status = 'processing' AND OLD.status <> 'processing'
    AND NEW.attempts <> OLD.attempts + 1) OR
  NOT (
    (OLD.status = 'pending' AND NEW.status IN (
      'pending', 'processing', 'superseded', 'failed'
    )) OR
    (OLD.status = 'processing' AND NEW.status IN (
      'processing', 'pending', 'awaiting-receipt',
      'enforced', 'rejected', 'quarantined', 'superseded', 'failed'
    )) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status IN (
      'awaiting-receipt', 'processing',
      'enforced', 'rejected', 'quarantined', 'superseded', 'failed'
    ))
  )
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime Run command dispatch transition');
END;

CREATE TABLE runtime_run_command_receipts (
  id TEXT PRIMARY KEY,
  command_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  previous_version INTEGER,
  session_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  command_sequence INTEGER NOT NULL CHECK (command_sequence >= 1),
  run_policy_revision INTEGER NOT NULL CHECK (run_policy_revision >= 1),
  goal_set_id TEXT NOT NULL,
  goal_set_revision INTEGER NOT NULL CHECK (goal_set_revision >= 1),
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  expected_run_state_version INTEGER NOT NULL CHECK (expected_run_state_version >= 1),
  target_run_state_version INTEGER NOT NULL CHECK (
    target_run_state_version = expected_run_state_version + 1
  ),
  source_session_sequence INTEGER NOT NULL CHECK (source_session_sequence >= 1),
  command_digest TEXT NOT NULL CHECK (length(command_digest) = 64),
  outcome TEXT NOT NULL CHECK (outcome IN (
    'accepted', 'enforced', 'duplicate', 'rejected', 'quarantined'
  )),
  original_outcome TEXT CHECK (
    original_outcome IS NULL OR original_outcome IN (
      'accepted', 'enforced', 'rejected', 'quarantined'
    )
  ),
  original_receipt_digest TEXT CHECK (
    original_receipt_digest IS NULL OR
    (length(original_receipt_digest) = 64
      AND original_receipt_digest NOT GLOB '*[^0-9a-f]*')
  ),
  receipt_json TEXT NOT NULL CHECK (
    json_valid(receipt_json) AND json_type(receipt_json) = 'object'
    AND COALESCE(
      json_extract(receipt_json, '$.commandId') = command_id
        AND json_extract(receipt_json, '$.outcome') = outcome
        AND json_extract(
          receipt_json, '$.runtimeAuthorizationGeneration'
        ) = runtime_authorization_generation
        AND json_extract(receipt_json, '$.binding.sessionId') = session_id
        AND json_extract(
          receipt_json, '$.binding.runtimeAssignmentId'
        ) = runtime_assignment_id
        AND json_extract(
          receipt_json, '$.binding.runtimeAssignmentGeneration'
        ) = runtime_assignment_generation
        AND json_extract(receipt_json, '$.binding.sandboxId') = sandbox_id
        AND json_extract(
          receipt_json, '$.binding.sandboxGeneration'
        ) = sandbox_generation
        AND json_extract(
          receipt_json, '$.binding.runtimePrincipalId'
        ) = runtime_principal_id,
      0
    )
    AND (
      outcome <> 'accepted' OR
      COALESCE(
        json_type(receipt_json, '$.effectRef') = 'text'
          AND length(json_extract(receipt_json, '$.effectRef')) BETWEEN 1 AND 1000,
        0
      )
    )
    AND (
      outcome <> 'enforced' OR
      COALESCE(
        json_type(receipt_json, '$.enforcedFence') = 'integer'
          AND json_extract(receipt_json, '$.enforcedFence') = target_run_state_version
          AND json_type(receipt_json, '$.effectRef') = 'text'
          AND length(json_extract(receipt_json, '$.effectRef')) BETWEEN 1 AND 1000,
        0
      )
    )
    AND (
      outcome <> 'rejected' OR
      COALESCE(
        json_type(receipt_json, '$.code') = 'text'
          AND length(json_extract(receipt_json, '$.code')) BETWEEN 1 AND 200
          AND json_type(receipt_json, '$.safeDetail') = 'text'
          AND length(json_extract(receipt_json, '$.safeDetail')) BETWEEN 1 AND 1000,
        0
      )
    )
    AND (
      outcome <> 'quarantined' OR
      COALESCE(
        json_type(receipt_json, '$.reason') = 'text'
          AND length(json_extract(receipt_json, '$.reason')) BETWEEN 1 AND 200
          AND json_type(receipt_json, '$.effectRef') = 'text'
          AND length(json_extract(receipt_json, '$.effectRef')) BETWEEN 1 AND 1000,
        0
      )
    )
    AND (
      outcome <> 'duplicate' OR
      COALESCE(
        json_type(receipt_json, '$.originalReceipt') = 'object'
          AND json_extract(receipt_json, '$.originalReceipt.commandId') = command_id
          AND json_extract(receipt_json, '$.originalReceipt.outcome') = original_outcome
          AND json_extract(receipt_json, '$.originalReceiptDigest') = original_receipt_digest
          AND json_extract(
            receipt_json, '$.originalReceipt.runtimeAuthorizationGeneration'
          ) = runtime_authorization_generation
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.sessionId'
          ) = session_id
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.teamId'
          ) = json_extract(receipt_json, '$.binding.teamId')
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.projectId'
          ) = json_extract(receipt_json, '$.binding.projectId')
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.runtimeAssignmentId'
          ) = runtime_assignment_id
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.runtimeAssignmentGeneration'
          ) = runtime_assignment_generation
          AND json_extract(receipt_json, '$.originalReceipt.binding.sandboxId') = sandbox_id
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.sandboxGeneration'
          ) = sandbox_generation
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.runtimePrincipalId'
          ) = runtime_principal_id
          AND (
            original_outcome <> 'accepted' OR
            (json_type(receipt_json, '$.originalReceipt.effectRef') = 'text'
              AND length(
                json_extract(receipt_json, '$.originalReceipt.effectRef')
              ) BETWEEN 1 AND 1000)
          )
          AND (
            original_outcome <> 'enforced' OR
            (json_type(receipt_json, '$.originalReceipt.enforcedFence') = 'integer'
              AND json_extract(
                receipt_json, '$.originalReceipt.enforcedFence'
              ) = target_run_state_version
              AND json_type(receipt_json, '$.originalReceipt.effectRef') = 'text'
              AND length(json_extract(receipt_json, '$.originalReceipt.effectRef')) BETWEEN 1 AND 1000)
          )
          AND (
            original_outcome <> 'rejected' OR
            (json_type(receipt_json, '$.originalReceipt.code') = 'text'
              AND length(json_extract(receipt_json, '$.originalReceipt.code')) BETWEEN 1 AND 200
              AND json_type(receipt_json, '$.originalReceipt.safeDetail') = 'text'
              AND length(
                json_extract(receipt_json, '$.originalReceipt.safeDetail')
              ) BETWEEN 1 AND 1000)
          )
          AND (
            original_outcome <> 'quarantined' OR
            (json_type(receipt_json, '$.originalReceipt.reason') = 'text'
              AND length(
                json_extract(receipt_json, '$.originalReceipt.reason')
              ) BETWEEN 1 AND 200
              AND json_type(receipt_json, '$.originalReceipt.effectRef') = 'text'
              AND length(
                json_extract(receipt_json, '$.originalReceipt.effectRef')
              ) BETWEEN 1 AND 1000)
          ),
        0
      )
    )
  ),
  receipt_digest TEXT NOT NULL CHECK (
    length(receipt_digest) = 64 AND receipt_digest NOT GLOB '*[^0-9a-f]*'
  ),
  received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= 0),
  UNIQUE (command_id, version),
  UNIQUE (command_id, receipt_digest),
  UNIQUE (id, command_id, outcome),
  CHECK (
    (version = 1 AND previous_version IS NULL) OR
    (version > 1 AND previous_version = version - 1)
  ),
  CHECK (
    (outcome = 'duplicate' AND original_outcome IS NOT NULL
      AND original_receipt_digest IS NOT NULL) OR
    (outcome <> 'duplicate' AND original_outcome IS NULL
      AND original_receipt_digest IS NULL)
  ),
  FOREIGN KEY (
    command_id, session_id, agent_run_id, command_sequence, run_policy_revision,
    goal_set_id, goal_set_revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation,
    expected_run_state_version, target_run_state_version,
    source_session_sequence, command_digest
  ) REFERENCES runtime_run_commands(
    id, session_id, agent_run_id, command_sequence, run_policy_revision,
    goal_set_id, goal_set_revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation,
    expected_run_state_version, target_run_state_version,
    source_session_sequence, command_digest
  ) ON DELETE RESTRICT,
  FOREIGN KEY (command_id, previous_version)
    REFERENCES runtime_run_command_receipts(command_id, version) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX one_terminal_runtime_run_receipt_per_command
  ON runtime_run_command_receipts(command_id)
  WHERE outcome IN ('enforced', 'rejected', 'quarantined');

CREATE TRIGGER runtime_run_command_receipts_immutable_update
BEFORE UPDATE ON runtime_run_command_receipts
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command receipts are immutable');
END;

CREATE TRIGGER runtime_run_command_receipts_json_scope_binding
BEFORE INSERT ON runtime_run_command_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_assignments assignment
  WHERE assignment.id = NEW.runtime_assignment_id
    AND assignment.session_id = NEW.session_id
    AND assignment.generation = NEW.runtime_assignment_generation
    AND assignment.sandbox_id = NEW.sandbox_id
    AND assignment.sandbox_generation = NEW.sandbox_generation
    AND assignment.runtime_principal_id = NEW.runtime_principal_id
    AND json_extract(NEW.receipt_json, '$.binding.teamId') = assignment.team_id
    AND json_extract(NEW.receipt_json, '$.binding.projectId') = assignment.project_id
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run receipt JSON scope does not match its binding');
END;

CREATE TRIGGER runtime_run_command_receipts_immutable_delete
BEFORE DELETE ON runtime_run_command_receipts
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command receipts are immutable');
END;

CREATE TRIGGER runtime_run_command_receipts_version_continuity
BEFORE INSERT ON runtime_run_command_receipts
WHEN NEW.previous_version IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM runtime_run_command_receipts previous
  WHERE previous.command_id = NEW.command_id
    AND previous.version = NEW.previous_version
    AND previous.received_at_ms <= NEW.received_at_ms
    AND (
      (previous.outcome = 'accepted' AND (
        NEW.outcome IN ('enforced', 'rejected', 'quarantined') OR
        (NEW.outcome = 'duplicate'
          AND NEW.original_outcome = 'accepted'
          AND NEW.original_receipt_digest = previous.receipt_digest)
      )) OR
      (previous.outcome IN ('enforced', 'rejected', 'quarantined')
        AND NEW.outcome = 'duplicate'
        AND NEW.original_outcome = previous.outcome
        AND NEW.original_receipt_digest = previous.receipt_digest) OR
      (previous.outcome = 'duplicate' AND previous.original_outcome = 'accepted' AND (
        NEW.outcome IN ('enforced', 'rejected', 'quarantined') OR
        (NEW.outcome = 'duplicate'
          AND NEW.original_outcome = 'accepted'
          AND NEW.original_receipt_digest = previous.original_receipt_digest)
      )) OR
      (previous.outcome = 'duplicate'
        AND previous.original_outcome IN ('enforced', 'rejected', 'quarantined')
        AND NEW.outcome = 'duplicate'
        AND NEW.original_outcome = previous.original_outcome
        AND NEW.original_receipt_digest = previous.original_receipt_digest)
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime Run receipt version continuity');
END;

CREATE TABLE runtime_run_command_effects (
  command_id TEXT PRIMARY KEY,
  receipt_id TEXT NOT NULL UNIQUE,
  receipt_outcome TEXT NOT NULL CHECK (receipt_outcome IN ('enforced', 'duplicate')),
  session_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  command_sequence INTEGER NOT NULL CHECK (command_sequence >= 1),
  expected_run_state_version INTEGER NOT NULL CHECK (expected_run_state_version >= 1),
  target_run_state_version INTEGER NOT NULL CHECK (
    target_run_state_version = expected_run_state_version + 1
  ),
  source_session_sequence INTEGER NOT NULL CHECK (source_session_sequence >= 1),
  applied_session_sequence INTEGER NOT NULL CHECK (
    applied_session_sequence > source_session_sequence
  ),
  effect_digest TEXT NOT NULL UNIQUE CHECK (
    length(effect_digest) = 64 AND effect_digest NOT GLOB '*[^0-9a-f]*'
  ),
  applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0),
  FOREIGN KEY (
    command_id, session_id, agent_run_id, command_sequence,
    expected_run_state_version, target_run_state_version, source_session_sequence
  ) REFERENCES runtime_run_commands(
    id, session_id, agent_run_id, command_sequence,
    expected_run_state_version, target_run_state_version, source_session_sequence
  ) ON DELETE RESTRICT,
  FOREIGN KEY (receipt_id, command_id, receipt_outcome)
    REFERENCES runtime_run_command_receipts(id, command_id, outcome) ON DELETE RESTRICT,
  FOREIGN KEY (session_id, applied_session_sequence)
    REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER runtime_run_command_effects_enforced_receipt
BEFORE INSERT ON runtime_run_command_effects
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_run_command_receipts receipt
  WHERE receipt.id = NEW.receipt_id
    AND receipt.command_id = NEW.command_id
    AND (
      receipt.outcome = 'enforced' OR
      (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced')
    )
    AND receipt.received_at_ms <= NEW.applied_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run effect requires an enforced receipt');
END;

CREATE TRIGGER runtime_run_command_effects_current_state
BEFORE INSERT ON runtime_run_command_effects
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_run_commands command
  JOIN runtime_run_command_dispatch dispatch
    ON dispatch.command_id = command.id
   AND dispatch.agent_run_id = command.agent_run_id
  JOIN agent_runs run
    ON run.id = command.agent_run_id
   AND run.session_id = command.session_id
  JOIN goal_sets goal_set
    ON goal_set.agent_run_id = run.id
   AND goal_set.revision = run.current_goal_set_revision
  JOIN sessions session ON session.id = run.session_id
  JOIN runtime_assignments assignment
    ON assignment.id = run.runtime_assignment_id
   AND assignment.session_id = run.session_id
  WHERE command.id = NEW.command_id
    AND dispatch.status IN ('processing', 'awaiting-receipt')
    AND dispatch.attempts >= 1
    AND run.state_version = NEW.expected_run_state_version
    AND run.current_policy_revision = command.run_policy_revision
    AND run.current_goal_set_revision = command.goal_set_revision
    AND goal_set.goal_set_id = command.goal_set_id
    AND run.runtime_assignment_id = command.runtime_assignment_id
    AND run.runtime_authorization_generation = command.runtime_authorization_generation
    AND session.runtime_authorization_generation = command.runtime_authorization_generation
    AND session.runtime_authorization_state = 'enforced'
    AND assignment.generation = command.runtime_assignment_generation
    AND assignment.sandbox_id = command.sandbox_id
    AND assignment.sandbox_generation = command.sandbox_generation
    AND assignment.runtime_principal_id = command.runtime_principal_id
    AND assignment.runtime_authorization_generation = command.runtime_authorization_generation
    AND assignment.status = 'ready'
    AND (
      (command.operation = 'run.pause' AND run.lifecycle = 'active') OR
      (command.operation = 'run.resume' AND run.lifecycle = 'paused') OR
      (command.operation = 'run.stop'
        AND run.lifecycle IN ('active', 'paused', 'agent-work-finished'))
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run effect does not match current dispatch and Run state');
END;

CREATE TRIGGER runtime_run_command_effects_event_binding
BEFORE INSERT ON runtime_run_command_effects
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_run_commands command
  JOIN session_events event
    ON event.session_id = NEW.session_id
   AND event.sequence = NEW.applied_session_sequence
  WHERE command.id = NEW.command_id
    AND command.agent_run_id = NEW.agent_run_id
    AND event.type = CASE command.operation
      WHEN 'run.pause' THEN 'run.paused'
      WHEN 'run.resume' THEN 'run.resumed'
      WHEN 'run.stop' THEN 'run.stopped'
    END
    AND json_extract(event.payload_json, '$.commandId') = NEW.command_id
    AND json_extract(event.payload_json, '$.agentRunId') = NEW.agent_run_id
    AND json_extract(
      event.payload_json, '$.fromRunStateVersion'
    ) = NEW.expected_run_state_version
    AND json_extract(
      event.payload_json, '$.toRunStateVersion'
    ) = NEW.target_run_state_version
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run effect event does not match its command');
END;

CREATE TRIGGER runtime_run_command_effects_immutable_update
BEFORE UPDATE ON runtime_run_command_effects
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command effects are immutable');
END;

CREATE TRIGGER runtime_run_command_effects_immutable_delete
BEFORE DELETE ON runtime_run_command_effects
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command effects are immutable');
END;

CREATE TRIGGER runtime_run_command_dispatch_terminal_evidence
BEFORE UPDATE OF status ON runtime_run_command_dispatch
WHEN
  (NEW.status = 'enforced' AND (
    NOT EXISTS (
      SELECT 1 FROM runtime_run_command_effects effect
      WHERE effect.command_id = NEW.command_id
    ) OR
    NOT EXISTS (
      SELECT 1
      FROM runtime_run_commands command
      JOIN agent_runs run
        ON run.id = command.agent_run_id
       AND run.session_id = command.session_id
      JOIN goal_sets goal_set
        ON goal_set.agent_run_id = run.id
       AND goal_set.revision = run.current_goal_set_revision
      JOIN sessions session ON session.id = run.session_id
      JOIN runtime_assignments assignment
        ON assignment.id = run.runtime_assignment_id
       AND assignment.session_id = run.session_id
      WHERE command.id = NEW.command_id
        AND run.lifecycle = command.target_lifecycle
        AND run.state_version = command.target_run_state_version
        AND run.current_policy_revision = command.run_policy_revision
        AND run.current_goal_set_revision = command.goal_set_revision
        AND goal_set.goal_set_id = command.goal_set_id
        AND run.runtime_assignment_id = command.runtime_assignment_id
        AND run.runtime_authorization_generation = command.runtime_authorization_generation
        AND session.runtime_authorization_generation = command.runtime_authorization_generation
        AND session.runtime_authorization_state = 'enforced'
        AND assignment.generation = command.runtime_assignment_generation
        AND assignment.sandbox_id = command.sandbox_id
        AND assignment.sandbox_generation = command.sandbox_generation
        AND assignment.runtime_principal_id = command.runtime_principal_id
        AND assignment.runtime_authorization_generation = command.runtime_authorization_generation
        AND assignment.status = 'ready'
    )
  )) OR
  (NEW.status IN ('rejected', 'quarantined') AND NOT EXISTS (
    SELECT 1 FROM runtime_run_command_receipts receipt
    WHERE receipt.command_id = NEW.command_id
      AND (
        receipt.outcome = NEW.status OR
        (receipt.outcome = 'duplicate' AND receipt.original_outcome = NEW.status)
      )
  ))
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run dispatch terminal state lacks durable evidence');
END;

CREATE TRIGGER runtime_run_referenced_session_events_immutable_update
BEFORE UPDATE ON session_events
WHEN
  EXISTS (
    SELECT 1 FROM runtime_run_commands command
    WHERE command.session_id = OLD.session_id
      AND command.source_session_sequence = OLD.sequence
  ) OR
  EXISTS (
    SELECT 1 FROM runtime_run_command_effects effect
    WHERE effect.session_id = OLD.session_id
      AND effect.applied_session_sequence = OLD.sequence
  )
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run journal events are immutable');
END;

CREATE TRIGGER runtime_run_referenced_session_events_immutable_delete
BEFORE DELETE ON session_events
WHEN
  EXISTS (
    SELECT 1 FROM runtime_run_commands command
    WHERE command.session_id = OLD.session_id
      AND command.source_session_sequence = OLD.sequence
  ) OR
  EXISTS (
    SELECT 1 FROM runtime_run_command_effects effect
    WHERE effect.session_id = OLD.session_id
      AND effect.applied_session_sequence = OLD.sequence
  )
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run journal events are immutable');
END;
`;

const RUNTIME_START_SCHEMA_V5 = `
DROP TRIGGER runtime_run_command_effects_current_state;
DROP TRIGGER runtime_run_command_effects_event_binding;
DROP TRIGGER runtime_run_command_dispatch_terminal_evidence;
DROP TRIGGER runtime_run_referenced_session_events_immutable_update;
DROP TRIGGER runtime_run_referenced_session_events_immutable_delete;

CREATE TABLE agent_runs_v5 (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  runtime_assignment_id TEXT NOT NULL,
  start_command_id TEXT UNIQUE,
  lifecycle TEXT NOT NULL CHECK (lifecycle IN (
    'starting', 'active', 'pausing', 'paused', 'agent-work-finished',
    'completed', 'failed', 'stopped', 'emergency-stopped'
  )),
  state_version INTEGER NOT NULL DEFAULT 1 CHECK (state_version >= 1),
  current_policy_revision INTEGER NOT NULL CHECK (current_policy_revision >= 1),
  current_goal_set_revision INTEGER NOT NULL CHECK (current_goal_set_revision >= 1),
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  final_review_version INTEGER NOT NULL DEFAULT 1 CHECK (final_review_version >= 1),
  created_by_user_id TEXT NOT NULL CHECK (length(created_by_user_id) BETWEEN 1 AND 300),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
  terminal_at_ms INTEGER,
  CHECK (
    (lifecycle IN ('completed', 'failed', 'stopped', 'emergency-stopped')
      AND terminal_at_ms IS NOT NULL) OR
    (lifecycle IN ('starting', 'active', 'pausing', 'paused', 'agent-work-finished')
      AND terminal_at_ms IS NULL)
  ),
  CHECK (lifecycle <> 'starting' OR start_command_id IS NOT NULL),
  UNIQUE (id, session_id),
  FOREIGN KEY (session_id, team_id, project_id)
    REFERENCES sessions(id, team_id, project_id) ON DELETE RESTRICT,
  FOREIGN KEY (runtime_assignment_id, session_id)
    REFERENCES runtime_assignments(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (id, current_policy_revision)
    REFERENCES run_policy_revisions(agent_run_id, revision)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (id, current_goal_set_revision)
    REFERENCES goal_sets(agent_run_id, revision)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (session_id, runtime_authorization_generation)
    REFERENCES runtime_authorization_epochs(session_id, generation)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (start_command_id, id)
    REFERENCES runtime_run_commands(id, agent_run_id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

INSERT INTO agent_runs_v5 (
  id, session_id, team_id, project_id, runtime_assignment_id, start_command_id,
  lifecycle, state_version, current_policy_revision, current_goal_set_revision,
  runtime_authorization_generation, final_review_version, created_by_user_id,
  created_at_ms, updated_at_ms, terminal_at_ms
)
SELECT
  id, session_id, team_id, project_id, runtime_assignment_id, NULL,
  lifecycle, state_version, current_policy_revision, current_goal_set_revision,
  runtime_authorization_generation, final_review_version, created_by_user_id,
  created_at_ms, updated_at_ms, terminal_at_ms
FROM agent_runs;

DROP TABLE agent_runs;
ALTER TABLE agent_runs_v5 RENAME TO agent_runs;

CREATE TRIGGER agent_runs_authorization_monotonic
BEFORE UPDATE OF runtime_authorization_generation ON agent_runs
WHEN NEW.runtime_authorization_generation < OLD.runtime_authorization_generation
BEGIN
  SELECT RAISE(ABORT, 'Run Runtime authorization generation cannot move backwards');
END;

CREATE TRIGGER agent_runs_state_version_monotonic
BEFORE UPDATE OF state_version, updated_at_ms ON agent_runs
WHEN
  NEW.state_version < OLD.state_version OR
  NEW.state_version > OLD.state_version + 1 OR
  NEW.updated_at_ms < OLD.updated_at_ms
BEGIN
  SELECT RAISE(ABORT, 'Invalid Agent Run state version transition');
END;

CREATE TRIGGER agent_runs_start_command_immutable
BEFORE UPDATE OF start_command_id ON agent_runs
WHEN NEW.start_command_id IS NOT OLD.start_command_id
BEGIN
  SELECT RAISE(ABORT, 'Agent Run start command identity is immutable');
END;

CREATE UNIQUE INDEX one_mutable_agent_run_per_session
  ON agent_runs(session_id)
  WHERE lifecycle IN ('starting', 'active', 'pausing', 'paused', 'agent-work-finished');

CREATE TABLE runtime_run_commands_v5 (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  command_sequence INTEGER NOT NULL CHECK (command_sequence >= 1),
  previous_command_sequence INTEGER,
  operation TEXT NOT NULL CHECK (
    operation IN ('run.start', 'run.pause', 'run.resume', 'run.stop')
  ),
  target_lifecycle TEXT NOT NULL CHECK (target_lifecycle IN ('active', 'paused', 'stopped')),
  expected_run_state_version INTEGER NOT NULL CHECK (expected_run_state_version >= 1),
  target_run_state_version INTEGER NOT NULL CHECK (
    target_run_state_version = expected_run_state_version + 1
  ),
  run_policy_revision INTEGER NOT NULL CHECK (run_policy_revision >= 1),
  goal_set_id TEXT NOT NULL CHECK (length(goal_set_id) BETWEEN 1 AND 300),
  goal_set_revision INTEGER NOT NULL CHECK (goal_set_revision >= 1),
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  source_session_sequence INTEGER NOT NULL CHECK (source_session_sequence >= 1),
  command_json TEXT NOT NULL CHECK (
    json_valid(command_json) AND json_type(command_json) = 'object'
    AND COALESCE(
        json_extract(command_json, '$.commandId') = id
        AND json_extract(command_json, '$.kind') = operation
        AND json_extract(command_json, '$.agentRunId') = agent_run_id
        AND json_extract(command_json, '$.runPolicyRevision') = run_policy_revision
        AND json_type(command_json, '$.projectCeilingRevision') = 'text'
        AND length(json_extract(command_json, '$.projectCeilingRevision')) BETWEEN 1 AND 300
        AND json_extract(
          command_json, '$.fromRunStateVersion'
        ) = expected_run_state_version
        AND json_extract(
          command_json, '$.toRunStateVersion'
        ) = target_run_state_version
        AND json_extract(
          command_json, '$.runtimeAuthorizationGeneration'
        ) = runtime_authorization_generation
        AND json_type(command_json, '$.causationId') = 'text'
        AND length(json_extract(command_json, '$.causationId')) BETWEEN 1 AND 300
        AND json_type(command_json, '$.actor') = 'object'
        AND COALESCE(json_extract(command_json, '$.actor.kind'), '') IN ('human', 'system')
        AND json_type(command_json, '$.actor.actorRef') = 'text'
        AND length(json_extract(command_json, '$.actor.actorRef')) BETWEEN 1 AND 300
        AND json_extract(command_json, '$.issuedAtMs') = created_at_ms
        AND json_extract(command_json, '$.deadlineAtMs') = deadline_at_ms
        AND json_extract(command_json, '$.authority.issuer') = 'team-session'
        AND json_type(command_json, '$.authority.issuerKeyId') = 'text'
        AND length(json_extract(command_json, '$.authority.issuerKeyId')) BETWEEN 1 AND 300
        AND json_extract(command_json, '$.authority.audience') = 'runtime'
        AND json_extract(command_json, '$.authority.capability') = operation
        AND json_extract(command_json, '$.authority.claimsDigest') = authority_digest
        AND json_type(command_json, '$.authority.issuedAtMs') = 'integer'
        AND json_extract(command_json, '$.authority.issuedAtMs') >= 0
        AND json_extract(command_json, '$.authority.issuedAtMs') <= created_at_ms
        AND json_type(command_json, '$.authority.expiresAtMs') = 'integer'
        AND json_extract(command_json, '$.authority.expiresAtMs') > created_at_ms
        AND json_type(command_json, '$.authority.signature') = 'text'
        AND length(json_extract(command_json, '$.authority.signature')) BETWEEN 1 AND 4000
        AND json_extract(command_json, '$.binding.sessionId') = session_id
        AND json_extract(
          command_json, '$.binding.runtimeAssignmentId'
        ) = runtime_assignment_id
        AND json_extract(
          command_json, '$.binding.runtimeAssignmentGeneration'
        ) = runtime_assignment_generation
        AND json_extract(command_json, '$.binding.sandboxId') = sandbox_id
        AND json_extract(
          command_json, '$.binding.sandboxGeneration'
        ) = sandbox_generation
        AND json_extract(
          command_json, '$.binding.runtimePrincipalId'
        ) = runtime_principal_id,
      0
    )
    AND COALESCE((
      (operation = 'run.start' AND json_type(command_json, '$.policy') = 'object') OR
      (operation = 'run.pause'
        AND COALESCE(json_extract(command_json, '$.reason'), '') IN (
          'human', 'attention_timeout', 'limit', 'safety'
        )) OR
      (operation = 'run.resume'
        AND json_type(command_json, '$.accountableAssigneePresent') = 'true'
        AND json_extract(command_json, '$.accountableAssigneePresent') = 1) OR
      (operation = 'run.stop'
        AND COALESCE(json_extract(command_json, '$.reason'), '') IN (
          'human', 'final_review_closed', 'superseded'
        ))
    ), 0)
  ),
  command_digest TEXT NOT NULL CHECK (
    length(command_digest) = 64 AND command_digest NOT GLOB '*[^0-9a-f]*'
  ),
  authority_digest TEXT NOT NULL CHECK (
    length(authority_digest) = 64 AND authority_digest NOT GLOB '*[^0-9a-f]*'
  ),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  deadline_at_ms INTEGER NOT NULL CHECK (deadline_at_ms > created_at_ms),
  UNIQUE (agent_run_id, command_sequence),
  UNIQUE (session_id, source_session_sequence),
  UNIQUE (id, agent_run_id),
  UNIQUE (
    id, session_id, agent_run_id, command_sequence,
    expected_run_state_version, target_run_state_version, source_session_sequence
  ),
  UNIQUE (
    id, session_id, agent_run_id, command_sequence, run_policy_revision,
    goal_set_id, goal_set_revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation,
    expected_run_state_version, target_run_state_version,
    source_session_sequence, command_digest
  ),
  CHECK (
    (command_sequence = 1 AND previous_command_sequence IS NULL) OR
    (command_sequence > 1 AND previous_command_sequence = command_sequence - 1)
  ),
  CHECK (
    (operation IN ('run.start', 'run.resume') AND target_lifecycle = 'active') OR
    (operation = 'run.pause' AND target_lifecycle = 'paused') OR
    (operation = 'run.stop' AND target_lifecycle = 'stopped')
  ),
  CHECK (
    operation <> 'run.start' OR (
      command_sequence = 1
      AND previous_command_sequence IS NULL
      AND expected_run_state_version = 1
      AND target_run_state_version = 2
      AND run_policy_revision = 1
      AND goal_set_revision = 1
    )
  ),
  FOREIGN KEY (session_id, source_session_sequence)
    REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT,
  FOREIGN KEY (agent_run_id, session_id)
    REFERENCES agent_runs(id, session_id) ON DELETE RESTRICT,
  FOREIGN KEY (agent_run_id, goal_set_id, goal_set_revision)
    REFERENCES goal_sets(agent_run_id, goal_set_id, revision) ON DELETE RESTRICT,
  FOREIGN KEY (
    agent_run_id, session_id, run_policy_revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation
  ) REFERENCES run_policy_revisions(
    agent_run_id, session_id, revision, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, runtime_authorization_generation
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    session_id, runtime_authorization_generation, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_authorization_epochs(
    session_id, generation, runtime_assignment_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (agent_run_id, previous_command_sequence)
    REFERENCES runtime_run_commands_v5(agent_run_id, command_sequence) ON DELETE RESTRICT
) STRICT;

INSERT INTO runtime_run_commands_v5
SELECT * FROM runtime_run_commands;

DROP TABLE runtime_run_commands;
ALTER TABLE runtime_run_commands_v5 RENAME TO runtime_run_commands;

CREATE TRIGGER runtime_run_commands_immutable_update
BEFORE UPDATE ON runtime_run_commands
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run commands are immutable');
END;

CREATE TRIGGER runtime_run_commands_immutable_delete
BEFORE DELETE ON runtime_run_commands
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run commands are immutable');
END;

CREATE TRIGGER runtime_run_commands_json_scope_binding
BEFORE INSERT ON runtime_run_commands
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_assignments assignment
  WHERE assignment.id = NEW.runtime_assignment_id
    AND assignment.session_id = NEW.session_id
    AND assignment.generation = NEW.runtime_assignment_generation
    AND assignment.sandbox_id = NEW.sandbox_id
    AND assignment.sandbox_generation = NEW.sandbox_generation
    AND assignment.runtime_principal_id = NEW.runtime_principal_id
    AND json_extract(NEW.command_json, '$.binding.teamId') = assignment.team_id
    AND json_extract(NEW.command_json, '$.binding.projectId') = assignment.project_id
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command JSON scope does not match its binding');
END;

CREATE TRIGGER runtime_run_commands_source_event_binding
BEFORE INSERT ON runtime_run_commands
WHEN NOT EXISTS (
  SELECT 1
  FROM session_events event
  JOIN run_policy_revisions policy
    ON policy.agent_run_id = NEW.agent_run_id
   AND policy.session_id = NEW.session_id
   AND policy.revision = NEW.run_policy_revision
  WHERE event.session_id = NEW.session_id
    AND event.sequence = NEW.source_session_sequence
    AND event.type = 'run.runtime-command.requested'
    AND json_extract(event.payload_json, '$.commandId') = NEW.id
    AND json_extract(event.payload_json, '$.agentRunId') = NEW.agent_run_id
    AND json_extract(event.payload_json, '$.operation') = NEW.operation
    AND json_extract(
      event.payload_json, '$.fromRunStateVersion'
    ) = NEW.expected_run_state_version
    AND json_extract(
      event.payload_json, '$.toRunStateVersion'
    ) = NEW.target_run_state_version
    AND json_extract(event.payload_json, '$.targetLifecycle') = NEW.target_lifecycle
    AND json_extract(NEW.command_json, '$.causationId') = event.event_id
    AND json_extract(NEW.command_json, '$.actor.kind') = event.actor_kind
    AND json_extract(NEW.command_json, '$.actor.actorRef') = event.actor_user_id
    AND json_extract(
      NEW.command_json, '$.projectCeilingRevision'
    ) = policy.project_ceiling_revision
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command source event does not match');
END;

CREATE TRIGGER runtime_run_commands_start_identity_binding
BEFORE INSERT ON runtime_run_commands
WHEN EXISTS (
  SELECT 1 FROM agent_runs run
  WHERE run.id = NEW.agent_run_id
    AND run.session_id = NEW.session_id
    AND run.start_command_id = NEW.id
    AND NEW.operation <> 'run.start'
)
BEGIN
  SELECT RAISE(ABORT, 'Agent Run start identity requires a run.start command');
END;

CREATE TRIGGER runtime_run_commands_current_state
BEFORE INSERT ON runtime_run_commands
WHEN NOT EXISTS (
  SELECT 1
  FROM agent_runs run
  JOIN sessions session ON session.id = run.session_id
  JOIN runtime_assignments assignment
    ON assignment.id = run.runtime_assignment_id
   AND assignment.session_id = run.session_id
  JOIN run_policy_revisions policy
    ON policy.agent_run_id = run.id
   AND policy.session_id = run.session_id
   AND policy.revision = run.current_policy_revision
  JOIN goal_sets goal_set
    ON goal_set.agent_run_id = run.id
   AND goal_set.revision = run.current_goal_set_revision
  WHERE run.id = NEW.agent_run_id
    AND run.session_id = NEW.session_id
    AND run.state_version = NEW.expected_run_state_version
    AND run.current_policy_revision = NEW.run_policy_revision
    AND run.current_goal_set_revision = NEW.goal_set_revision
    AND goal_set.goal_set_id = NEW.goal_set_id
    AND run.runtime_assignment_id = NEW.runtime_assignment_id
    AND run.runtime_authorization_generation = NEW.runtime_authorization_generation
    AND session.runtime_authorization_generation = NEW.runtime_authorization_generation
    AND session.runtime_authorization_state = 'enforced'
    AND assignment.generation = NEW.runtime_assignment_generation
    AND assignment.sandbox_id = NEW.sandbox_id
    AND assignment.sandbox_generation = NEW.sandbox_generation
    AND assignment.runtime_principal_id = NEW.runtime_principal_id
    AND assignment.runtime_authorization_generation = NEW.runtime_authorization_generation
    AND assignment.status = 'ready'
    AND (NEW.operation <> 'run.start' OR run.start_command_id = NEW.id)
    AND (
      (NEW.operation = 'run.start' AND run.lifecycle = 'starting') OR
      (NEW.operation = 'run.pause' AND run.lifecycle = 'active') OR
      (NEW.operation = 'run.resume' AND run.lifecycle IN ('paused', 'agent-work-finished')) OR
      (NEW.operation = 'run.stop'
        AND run.lifecycle IN ('active', 'paused', 'agent-work-finished'))
    )
    AND (
      NEW.operation <> 'run.start' OR (
        json_extract(NEW.command_json, '$.policy.agentRunId') = NEW.agent_run_id
        AND json_extract(NEW.command_json, '$.policy.revision') = NEW.run_policy_revision
        AND json_extract(NEW.command_json, '$.policy.digest') = policy.digest
        AND json_extract(
          NEW.command_json, '$.policy.policyBodyDigest'
        ) = policy.policy_body_digest
        AND json_extract(
          NEW.command_json, '$.policy.projectCeilingRevision'
        ) = policy.project_ceiling_revision
        AND json_extract(
          NEW.command_json, '$.policy.initialGoalSet.agentRunId'
        ) = NEW.agent_run_id
        AND json_extract(
          NEW.command_json, '$.policy.initialGoalSet.goalSetId'
        ) = NEW.goal_set_id
        AND json_extract(
          NEW.command_json, '$.policy.initialGoalSet.revision'
        ) = NEW.goal_set_revision
        AND json_extract(
          NEW.command_json, '$.policy.initialGoalSet.digest'
        ) = goal_set.digest
        AND json_extract(
          NEW.command_json, '$.policy.runtimeAuthorizationGeneration'
        ) = NEW.runtime_authorization_generation
        AND json_extract(
          NEW.command_json, '$.policy.binding.runtimeAssignmentId'
        ) = NEW.runtime_assignment_id
        AND json_extract(
          NEW.command_json, '$.policy.binding.runtimeAssignmentGeneration'
        ) = NEW.runtime_assignment_generation
        AND json_extract(
          NEW.command_json, '$.policy.binding.sandboxId'
        ) = NEW.sandbox_id
        AND json_extract(
          NEW.command_json, '$.policy.binding.sandboxGeneration'
        ) = NEW.sandbox_generation
        AND json_extract(
          NEW.command_json, '$.policy.binding.runtimePrincipalId'
        ) = NEW.runtime_principal_id
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command does not match current Run state');
END;

CREATE TABLE runtime_run_command_dispatch_v5 (
  command_id TEXT PRIMARY KEY,
  agent_run_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'pending', 'processing', 'awaiting-receipt', 'compensating',
    'enforced', 'rejected', 'quarantined', 'superseded', 'failed'
  )),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at_ms INTEGER NOT NULL CHECK (available_at_ms >= created_at_ms),
  lease_owner TEXT,
  lease_expires_at_ms INTEGER,
  last_safe_error_code TEXT CHECK (
    last_safe_error_code IS NULL OR length(last_safe_error_code) BETWEEN 1 AND 200
  ),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
  terminal_at_ms INTEGER,
  CHECK (
    (status = 'processing'
      AND lease_owner IS NOT NULL AND length(lease_owner) BETWEEN 1 AND 300
      AND lease_expires_at_ms IS NOT NULL AND lease_expires_at_ms > updated_at_ms) OR
    (status <> 'processing' AND lease_owner IS NULL AND lease_expires_at_ms IS NULL)
  ),
  CHECK (
    (status IN ('enforced', 'rejected', 'quarantined', 'superseded', 'failed')
      AND terminal_at_ms IS NOT NULL AND terminal_at_ms >= created_at_ms) OR
    (status IN ('pending', 'processing', 'awaiting-receipt', 'compensating')
      AND terminal_at_ms IS NULL)
  ),
  FOREIGN KEY (command_id, agent_run_id)
    REFERENCES runtime_run_commands(id, agent_run_id) ON DELETE RESTRICT
) STRICT;

INSERT INTO runtime_run_command_dispatch_v5 (
  command_id, agent_run_id, status, attempts, available_at_ms,
  lease_owner, lease_expires_at_ms, last_safe_error_code,
  created_at_ms, updated_at_ms, terminal_at_ms
)
SELECT
  command_id, agent_run_id,
  CASE
    WHEN status = 'processing' OR (
      status = 'pending' AND (
        attempts > 0 OR EXISTS (
          SELECT 1 FROM runtime_run_command_receipts receipt
          WHERE receipt.command_id = runtime_run_command_dispatch.command_id
        )
      )
    )
      THEN 'awaiting-receipt'
    ELSE status
  END,
  attempts, updated_at_ms,
  CASE WHEN status = 'processing' THEN NULL ELSE lease_owner END,
  CASE WHEN status = 'processing' THEN NULL ELSE lease_expires_at_ms END,
  CASE
    WHEN status = 'processing' OR (
      status = 'pending' AND (
        attempts > 0 OR EXISTS (
          SELECT 1 FROM runtime_run_command_receipts receipt
          WHERE receipt.command_id = runtime_run_command_dispatch.command_id
        )
      )
    )
      THEN 'migration_dispatch_uncertain'
    ELSE last_safe_error_code
  END,
  created_at_ms, updated_at_ms, terminal_at_ms
FROM runtime_run_command_dispatch;

DROP TABLE runtime_run_command_dispatch;
ALTER TABLE runtime_run_command_dispatch_v5 RENAME TO runtime_run_command_dispatch;

CREATE UNIQUE INDEX one_unresolved_runtime_run_command_per_run
  ON runtime_run_command_dispatch(agent_run_id)
  WHERE status IN ('pending', 'processing', 'awaiting-receipt', 'compensating');

CREATE INDEX runtime_run_command_dispatch_claimable
  ON runtime_run_command_dispatch(status, available_at_ms, created_at_ms, command_id);

CREATE TRIGGER runtime_run_command_dispatch_identity_immutable
BEFORE UPDATE OF command_id, agent_run_id, created_at_ms ON runtime_run_command_dispatch
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command dispatch identity is immutable');
END;

CREATE TRIGGER runtime_run_command_dispatch_initial_state
BEFORE INSERT ON runtime_run_command_dispatch
WHEN NEW.status <> 'pending' OR NEW.attempts <> 0 OR
  NEW.available_at_ms <> NEW.created_at_ms OR
  NEW.lease_owner IS NOT NULL OR NEW.lease_expires_at_ms IS NOT NULL OR
  NEW.last_safe_error_code IS NOT NULL OR NEW.terminal_at_ms IS NOT NULL OR
  NEW.updated_at_ms <> NEW.created_at_ms
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command dispatch must begin pending');
END;

CREATE TRIGGER runtime_run_command_dispatch_immutable_delete
BEFORE DELETE ON runtime_run_command_dispatch
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command dispatch cannot be deleted');
END;

CREATE TRIGGER runtime_run_command_dispatch_valid_transition
BEFORE UPDATE ON runtime_run_command_dispatch
WHEN
  OLD.status IN ('enforced', 'rejected', 'quarantined', 'superseded', 'failed') OR
  NEW.updated_at_ms < OLD.updated_at_ms OR
  NOT (
    (OLD.status = 'pending' AND NEW.status = 'processing'
      AND NEW.attempts = OLD.attempts + 1
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.updated_at_ms >= OLD.available_at_ms
      AND (
        OLD.attempts = 0 OR COALESCE(OLD.last_safe_error_code IN (
            'invalid_input', 'invalid_authority', 'authority_verification_failed',
            'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
            'lease_expired_before_dispatch'
          ), 0)
      )) OR
    (OLD.status = 'pending' AND NEW.status = 'pending'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND (
        OLD.attempts = 0 OR COALESCE(
          NEW.last_safe_error_code = OLD.last_safe_error_code,
          0
        )
      )) OR
    (OLD.status = 'pending' AND NEW.status = 'failed'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND COALESCE(NEW.last_safe_error_code IN (
          'invalid_input', 'invalid_authority', 'authority_verification_failed',
          'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
          'lease_expired_before_dispatch'
        ), 0)
      AND (
        OLD.attempts = 0 OR COALESCE(
          NEW.last_safe_error_code = OLD.last_safe_error_code,
          0
        )
      )) OR
    (OLD.status = 'pending' AND NEW.status = 'superseded'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.last_safe_error_code = 'state_fence_superseded'
      AND (
        OLD.attempts = 0 OR COALESCE(OLD.last_safe_error_code IN (
            'invalid_input', 'invalid_authority', 'authority_verification_failed',
            'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
            'lease_expired_before_dispatch'
          ), 0)
      )) OR
    (OLD.status = 'processing' AND NEW.status = 'processing'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.lease_owner = OLD.lease_owner
      AND NEW.updated_at_ms < OLD.lease_expires_at_ms
      AND NEW.lease_expires_at_ms >= OLD.lease_expires_at_ms) OR
    (OLD.status = 'processing' AND NEW.status = 'pending'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND NEW.updated_at_ms < OLD.lease_expires_at_ms
      AND COALESCE(NEW.last_safe_error_code IN (
          'invalid_input', 'invalid_authority', 'authority_verification_failed',
          'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
          'lease_expired_before_dispatch'
        ), 0)
      AND NOT EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
      )) OR
    (OLD.status = 'processing' AND NEW.status = 'awaiting-receipt'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms) OR
    (OLD.status = 'processing' AND NEW.status = 'compensating'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
          AND (
            receipt.outcome = 'enforced' OR
            (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced')
          )
      )) OR
    (OLD.status = 'processing' AND NEW.status IN (
        'enforced', 'rejected', 'quarantined'
      )
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status = 'awaiting-receipt'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status = 'compensating'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
          AND (
            receipt.outcome = 'enforced' OR
            (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced')
          )
      )) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status IN (
        'enforced', 'rejected', 'quarantined'
      )
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms)
  )
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime Run command dispatch transition');
END;

CREATE TRIGGER runtime_run_command_receipts_dispatch_state
BEFORE INSERT ON runtime_run_command_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_run_command_dispatch dispatch
  WHERE dispatch.command_id = NEW.command_id
    AND dispatch.agent_run_id = NEW.agent_run_id
    AND dispatch.status IN ('processing', 'awaiting-receipt')
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command dispatch is not accepting receipts');
END;

CREATE TRIGGER runtime_run_command_effects_current_state
BEFORE INSERT ON runtime_run_command_effects
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_run_commands command
  JOIN runtime_run_command_dispatch dispatch
    ON dispatch.command_id = command.id
   AND dispatch.agent_run_id = command.agent_run_id
  JOIN agent_runs run
    ON run.id = command.agent_run_id
   AND run.session_id = command.session_id
  JOIN goal_sets goal_set
    ON goal_set.agent_run_id = run.id
   AND goal_set.revision = run.current_goal_set_revision
  JOIN sessions session ON session.id = run.session_id
  JOIN runtime_assignments assignment
    ON assignment.id = run.runtime_assignment_id
   AND assignment.session_id = run.session_id
  WHERE command.id = NEW.command_id
    AND dispatch.status IN ('processing', 'awaiting-receipt')
    AND dispatch.attempts >= 1
    AND run.state_version = NEW.expected_run_state_version
    AND run.current_policy_revision = command.run_policy_revision
    AND run.current_goal_set_revision = command.goal_set_revision
    AND goal_set.goal_set_id = command.goal_set_id
    AND run.runtime_assignment_id = command.runtime_assignment_id
    AND run.runtime_authorization_generation = command.runtime_authorization_generation
    AND session.runtime_authorization_generation = command.runtime_authorization_generation
    AND session.runtime_authorization_state = 'enforced'
    AND assignment.generation = command.runtime_assignment_generation
    AND assignment.sandbox_id = command.sandbox_id
    AND assignment.sandbox_generation = command.sandbox_generation
    AND assignment.runtime_principal_id = command.runtime_principal_id
    AND assignment.runtime_authorization_generation = command.runtime_authorization_generation
    AND assignment.status = 'ready'
    AND (
      (command.operation = 'run.start' AND run.lifecycle = 'starting') OR
      (command.operation = 'run.pause' AND run.lifecycle = 'active') OR
      (command.operation = 'run.resume'
        AND run.lifecycle IN ('paused', 'agent-work-finished')) OR
      (command.operation = 'run.stop'
        AND run.lifecycle IN ('active', 'paused', 'agent-work-finished'))
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run effect does not match current dispatch and Run state');
END;

CREATE TRIGGER runtime_run_command_effects_event_binding
BEFORE INSERT ON runtime_run_command_effects
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_run_commands command
  JOIN session_events event
    ON event.session_id = NEW.session_id
   AND event.sequence = NEW.applied_session_sequence
  WHERE command.id = NEW.command_id
    AND command.agent_run_id = NEW.agent_run_id
    AND event.type = CASE command.operation
      WHEN 'run.start' THEN 'run.started'
      WHEN 'run.pause' THEN 'run.paused'
      WHEN 'run.resume' THEN 'run.resumed'
      WHEN 'run.stop' THEN 'run.stopped'
    END
    AND json_extract(event.payload_json, '$.commandId') = NEW.command_id
    AND json_extract(event.payload_json, '$.agentRunId') = NEW.agent_run_id
    AND json_extract(
      event.payload_json, '$.fromRunStateVersion'
    ) = NEW.expected_run_state_version
    AND json_extract(
      event.payload_json, '$.toRunStateVersion'
    ) = NEW.target_run_state_version
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run effect event does not match its command');
END;

CREATE TRIGGER agent_runs_runtime_lifecycle_requires_effect
BEFORE UPDATE OF lifecycle, state_version ON agent_runs
WHEN (
  (OLD.lifecycle = 'starting' AND NEW.lifecycle = 'active') OR
  (OLD.lifecycle = 'active' AND NEW.lifecycle = 'paused') OR
  (OLD.lifecycle IN ('paused', 'agent-work-finished') AND NEW.lifecycle = 'active') OR
  (OLD.lifecycle IN ('active', 'paused', 'agent-work-finished')
    AND NEW.lifecycle = 'stopped')
) AND NOT EXISTS (
  SELECT 1
  FROM runtime_run_command_effects effect
  JOIN runtime_run_commands command ON command.id = effect.command_id
  WHERE effect.agent_run_id = OLD.id
    AND effect.session_id = OLD.session_id
    AND effect.expected_run_state_version = OLD.state_version
    AND effect.target_run_state_version = NEW.state_version
    AND command.target_lifecycle = NEW.lifecycle
    AND (
      (OLD.lifecycle = 'starting' AND command.operation = 'run.start') OR
      (OLD.lifecycle = 'active' AND NEW.lifecycle = 'paused'
        AND command.operation = 'run.pause') OR
      (OLD.lifecycle IN ('paused', 'agent-work-finished') AND NEW.lifecycle = 'active'
        AND command.operation = 'run.resume') OR
      (NEW.lifecycle = 'stopped' AND command.operation = 'run.stop')
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime-backed Agent Run lifecycle transition lacks an enforced effect');
END;

CREATE TRIGGER agent_runs_start_failure_requires_terminal_dispatch
BEFORE UPDATE OF lifecycle, state_version ON agent_runs
WHEN OLD.lifecycle = 'starting' AND NEW.lifecycle = 'failed' AND NOT EXISTS (
  SELECT 1
  FROM runtime_run_commands command
  JOIN runtime_run_command_dispatch dispatch
    ON dispatch.command_id = command.id
   AND dispatch.agent_run_id = command.agent_run_id
  WHERE command.id = OLD.start_command_id
    AND command.agent_run_id = OLD.id
    AND command.session_id = OLD.session_id
    AND command.operation = 'run.start'
    AND command.expected_run_state_version = OLD.state_version
    AND command.target_run_state_version = NEW.state_version
    AND NEW.state_version = OLD.state_version + 1
    AND (
      (dispatch.status = 'failed' AND dispatch.last_safe_error_code IS NOT NULL) OR
      (dispatch.status IN ('rejected', 'quarantined') AND EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = command.id
          AND (
            receipt.outcome = dispatch.status OR
            (receipt.outcome = 'duplicate' AND receipt.original_outcome = dispatch.status)
          )
      ))
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Agent Run start failure lacks a terminal dispatch proof');
END;

CREATE TRIGGER agent_runs_starting_exit_valid
BEFORE UPDATE OF lifecycle ON agent_runs
WHEN OLD.lifecycle = 'starting' AND NEW.lifecycle NOT IN ('starting', 'active', 'pausing', 'failed')
BEGIN
  SELECT RAISE(ABORT, 'Invalid Agent Run starting lifecycle transition');
END;

CREATE TRIGGER runtime_run_command_dispatch_terminal_evidence
BEFORE UPDATE OF status ON runtime_run_command_dispatch
WHEN
  (NEW.status = 'enforced' AND (
    NOT EXISTS (
      SELECT 1 FROM runtime_run_command_effects effect
      WHERE effect.command_id = NEW.command_id
    ) OR
    NOT EXISTS (
      SELECT 1
      FROM runtime_run_commands command
      JOIN agent_runs run
        ON run.id = command.agent_run_id
       AND run.session_id = command.session_id
      JOIN goal_sets goal_set
        ON goal_set.agent_run_id = run.id
       AND goal_set.revision = run.current_goal_set_revision
      JOIN sessions session ON session.id = run.session_id
      JOIN runtime_assignments assignment
        ON assignment.id = run.runtime_assignment_id
       AND assignment.session_id = run.session_id
      WHERE command.id = NEW.command_id
        AND run.lifecycle = command.target_lifecycle
        AND run.state_version = command.target_run_state_version
        AND run.current_policy_revision = command.run_policy_revision
        AND run.current_goal_set_revision = command.goal_set_revision
        AND goal_set.goal_set_id = command.goal_set_id
        AND run.runtime_assignment_id = command.runtime_assignment_id
        AND run.runtime_authorization_generation = command.runtime_authorization_generation
        AND session.runtime_authorization_generation = command.runtime_authorization_generation
        AND session.runtime_authorization_state = 'enforced'
        AND assignment.generation = command.runtime_assignment_generation
        AND assignment.sandbox_id = command.sandbox_id
        AND assignment.sandbox_generation = command.sandbox_generation
        AND assignment.runtime_principal_id = command.runtime_principal_id
        AND assignment.runtime_authorization_generation = command.runtime_authorization_generation
        AND assignment.status = 'ready'
    )
  )) OR
  (NEW.status IN ('rejected', 'quarantined') AND NOT EXISTS (
    SELECT 1 FROM runtime_run_command_receipts receipt
    WHERE receipt.command_id = NEW.command_id
      AND (
        receipt.outcome = NEW.status OR
        (receipt.outcome = 'duplicate' AND receipt.original_outcome = NEW.status)
      )
  ))
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run dispatch terminal state lacks durable evidence');
END;

CREATE TRIGGER runtime_run_referenced_session_events_immutable_update
BEFORE UPDATE ON session_events
WHEN
  EXISTS (
    SELECT 1 FROM runtime_run_commands command
    WHERE command.session_id = OLD.session_id
      AND command.source_session_sequence = OLD.sequence
  ) OR
  EXISTS (
    SELECT 1 FROM runtime_run_command_effects effect
    WHERE effect.session_id = OLD.session_id
      AND effect.applied_session_sequence = OLD.sequence
  )
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run journal events are immutable');
END;

CREATE TRIGGER runtime_run_referenced_session_events_immutable_delete
BEFORE DELETE ON session_events
WHEN
  EXISTS (
    SELECT 1 FROM runtime_run_commands command
    WHERE command.session_id = OLD.session_id
      AND command.source_session_sequence = OLD.sequence
  ) OR
  EXISTS (
    SELECT 1 FROM runtime_run_command_effects effect
    WHERE effect.session_id = OLD.session_id
      AND effect.applied_session_sequence = OLD.sequence
  )
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run journal events are immutable');
END;
`;

const RUNTIME_RECEIPT_FOLLOW_SCHEMA_V6 = `
CREATE TRIGGER runtime_run_command_dispatch_interlock_initial_state
BEFORE INSERT ON runtime_run_command_dispatch
WHEN NEW.dispatch_interlock_acquired_at_ms IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run dispatch interlock must begin unacquired');
END;

DROP TRIGGER runtime_run_command_dispatch_valid_transition;

CREATE TRIGGER runtime_run_command_dispatch_valid_transition
BEFORE UPDATE ON runtime_run_command_dispatch
WHEN
  OLD.status IN ('enforced', 'rejected', 'quarantined', 'superseded', 'failed') OR
  NEW.updated_at_ms < OLD.updated_at_ms OR
  NOT (
    (OLD.status = 'pending' AND NEW.status = 'processing'
      AND NEW.attempts = OLD.attempts + 1
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.updated_at_ms >= OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS NULL
      AND (
        OLD.attempts = 0 OR COALESCE(OLD.last_safe_error_code IN (
            'invalid_input', 'invalid_authority', 'authority_verification_failed',
            'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
            'lease_expired_before_dispatch'
          ), 0)
      )) OR
    (OLD.status = 'pending' AND NEW.status = 'pending'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND (
        OLD.attempts = 0 OR COALESCE(
          NEW.last_safe_error_code = OLD.last_safe_error_code,
          0
        )
      )) OR
    (OLD.status = 'pending' AND NEW.status = 'failed'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND COALESCE(NEW.last_safe_error_code IN (
          'invalid_input', 'invalid_authority', 'authority_verification_failed',
          'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
          'lease_expired_before_dispatch'
        ), 0)
      AND (
        OLD.attempts = 0 OR COALESCE(
          NEW.last_safe_error_code = OLD.last_safe_error_code,
          0
        )
      )) OR
    (OLD.status = 'pending' AND NEW.status = 'superseded'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND NEW.last_safe_error_code = 'state_fence_superseded'
      AND (
        OLD.attempts = 0 OR COALESCE(OLD.last_safe_error_code IN (
            'invalid_input', 'invalid_authority', 'authority_verification_failed',
            'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
            'lease_expired_before_dispatch'
          ), 0)
      )) OR
    (OLD.status = 'processing' AND NEW.status = 'processing'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.lease_owner = OLD.lease_owner
      AND NEW.updated_at_ms < OLD.lease_expires_at_ms
      AND NEW.lease_expires_at_ms >= OLD.lease_expires_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.dispatch_interlock_acquired_at_ms = NEW.updated_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms < NEW.lease_expires_at_ms) OR
    (OLD.status = 'processing' AND NEW.status = 'pending'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND COALESCE(NEW.last_safe_error_code IN (
          'invalid_input', 'invalid_authority', 'authority_verification_failed',
          'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
          'lease_expired_before_dispatch'
        ), 0)
      AND (
        NEW.updated_at_ms < OLD.lease_expires_at_ms OR (
          OLD.dispatch_interlock_acquired_at_ms IS NULL
          AND NEW.last_safe_error_code IN (
            'lease_expired_before_dispatch', 'deadline_expired'
          )
          AND NEW.updated_at_ms >= OLD.lease_expires_at_ms
        )
      )
      AND NOT EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
      )) OR
    (OLD.status = 'processing' AND NEW.status = 'superseded'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.updated_at_ms < OLD.lease_expires_at_ms
      AND NEW.last_safe_error_code = 'state_fence_superseded'
      AND NOT EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
      )) OR
    (OLD.status = 'processing' AND NEW.status = 'awaiting-receipt'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NOT NULL
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms) OR
    (OLD.status = 'processing' AND NEW.status = 'compensating'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
          AND (
            receipt.outcome = 'enforced' OR
            (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced')
          )
      )) OR
    (OLD.status = 'processing' AND NEW.status IN (
        'enforced', 'rejected', 'quarantined'
      )
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status = 'awaiting-receipt'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status = 'compensating'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
          AND (
            receipt.outcome = 'enforced' OR
            (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced')
          )
      )) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status IN (
        'enforced', 'rejected', 'quarantined'
      )
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms)
  )
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime Run command dispatch transition');
END;

DROP TRIGGER runtime_run_command_receipts_dispatch_state;

CREATE TRIGGER runtime_run_command_receipts_dispatch_state
BEFORE INSERT ON runtime_run_command_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_run_command_dispatch dispatch
  WHERE dispatch.command_id = NEW.command_id
    AND dispatch.agent_run_id = NEW.agent_run_id
    AND (
      (dispatch.status = 'processing'
        AND dispatch.dispatch_interlock_acquired_at_ms IS NOT NULL) OR
      dispatch.status = 'awaiting-receipt'
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run command dispatch is not accepting receipts');
END;

CREATE TRIGGER sessions_runtime_lifecycle_dispatch_interlock
BEFORE UPDATE OF status, runtime_authorization_generation, runtime_authorization_state ON sessions
WHEN (
  NEW.status <> OLD.status OR
  NEW.runtime_authorization_generation <> OLD.runtime_authorization_generation OR
  NEW.runtime_authorization_state <> OLD.runtime_authorization_state
) AND EXISTS (
  SELECT 1
  FROM runtime_run_commands command
  JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
  WHERE command.session_id = OLD.id
    AND dispatch.status = 'processing'
    AND dispatch.dispatch_interlock_acquired_at_ms IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM runtime_run_command_receipts receipt
      WHERE receipt.command_id = command.id
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Session trust cannot change across an acquired Runtime dispatch interlock');
END;

CREATE TRIGGER runtime_assignments_lifecycle_dispatch_interlock
BEFORE UPDATE OF status, runtime_authorization_generation ON runtime_assignments
WHEN (
  NEW.status <> OLD.status OR
  NEW.runtime_authorization_generation <> OLD.runtime_authorization_generation
) AND EXISTS (
  SELECT 1
  FROM runtime_run_commands command
  JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
  WHERE command.runtime_assignment_id = OLD.id
    AND dispatch.status = 'processing'
    AND dispatch.dispatch_interlock_acquired_at_ms IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM runtime_run_command_receipts receipt
      WHERE receipt.command_id = command.id
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Assignment trust cannot change across an acquired dispatch interlock');
END;

CREATE TRIGGER agent_runs_lifecycle_dispatch_interlock
BEFORE UPDATE OF lifecycle, state_version, current_policy_revision, current_goal_set_revision,
  runtime_assignment_id, runtime_authorization_generation ON agent_runs
WHEN (
  NEW.lifecycle <> OLD.lifecycle OR
  NEW.state_version <> OLD.state_version OR
  NEW.current_policy_revision <> OLD.current_policy_revision OR
  NEW.current_goal_set_revision <> OLD.current_goal_set_revision OR
  NEW.runtime_assignment_id <> OLD.runtime_assignment_id OR
  NEW.runtime_authorization_generation <> OLD.runtime_authorization_generation
) AND EXISTS (
  SELECT 1
  FROM runtime_run_commands command
  JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
  WHERE command.agent_run_id = OLD.id
    AND dispatch.status = 'processing'
    AND dispatch.dispatch_interlock_acquired_at_ms IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM runtime_run_command_receipts receipt
      WHERE receipt.command_id = command.id
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Agent Run trust cannot change across an acquired Runtime dispatch interlock');
END;

CREATE TRIGGER run_policy_revisions_enforcer_set_binding
BEFORE INSERT ON run_policy_revisions
WHEN NEW.required_effect_enforcer_set_digest IS NULL OR NOT EXISTS (
  SELECT 1 FROM runtime_authorization_epochs epoch
  WHERE epoch.session_id = NEW.session_id
    AND epoch.generation = NEW.runtime_authorization_generation
    AND epoch.runtime_assignment_id = NEW.runtime_assignment_id
    AND epoch.runtime_assignment_generation = NEW.runtime_assignment_generation
    AND epoch.sandbox_id = NEW.sandbox_id
    AND epoch.sandbox_generation = NEW.sandbox_generation
    AND epoch.runtime_principal_id = NEW.runtime_principal_id
    AND epoch.effect_enforcer_set_digest = NEW.required_effect_enforcer_set_digest
)
BEGIN
  SELECT RAISE(ABORT, 'Run policy effect-enforcer set does not match its authorization epoch');
END;

CREATE TRIGGER runtime_run_commands_enforcer_set_binding
BEFORE INSERT ON runtime_run_commands
WHEN NEW.required_effect_enforcer_set_digest IS NULL OR
  COALESCE(
    json_extract(NEW.command_json, '$.requiredEffectEnforcerSetDigest') =
      NEW.required_effect_enforcer_set_digest,
    0
  ) = 0 OR
  (NEW.operation = 'run.start' AND COALESCE(
    json_extract(NEW.command_json, '$.policy.requiredEffectEnforcerSetDigest') =
      NEW.required_effect_enforcer_set_digest,
    0
  ) = 0) OR NOT EXISTS (
    SELECT 1
    FROM run_policy_revisions policy
    JOIN runtime_authorization_epochs epoch
      ON epoch.session_id = policy.session_id
     AND epoch.generation = policy.runtime_authorization_generation
     AND epoch.runtime_assignment_id = policy.runtime_assignment_id
     AND epoch.runtime_assignment_generation = policy.runtime_assignment_generation
     AND epoch.sandbox_id = policy.sandbox_id
     AND epoch.sandbox_generation = policy.sandbox_generation
     AND epoch.runtime_principal_id = policy.runtime_principal_id
    WHERE policy.agent_run_id = NEW.agent_run_id
      AND policy.session_id = NEW.session_id
      AND policy.revision = NEW.run_policy_revision
      AND policy.runtime_assignment_id = NEW.runtime_assignment_id
      AND policy.runtime_assignment_generation = NEW.runtime_assignment_generation
      AND policy.sandbox_id = NEW.sandbox_id
      AND policy.sandbox_generation = NEW.sandbox_generation
      AND policy.runtime_principal_id = NEW.runtime_principal_id
      AND policy.runtime_authorization_generation = NEW.runtime_authorization_generation
      AND policy.required_effect_enforcer_set_digest =
        NEW.required_effect_enforcer_set_digest
      AND epoch.effect_enforcer_set_digest = NEW.required_effect_enforcer_set_digest
  )
BEGIN
  SELECT RAISE(ABORT, 'Runtime command effect-enforcer set does not match policy and epoch');
END;

CREATE TRIGGER runtime_run_command_receipts_enforcement_proof
BEFORE INSERT ON runtime_run_command_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_run_commands command
  WHERE command.id = NEW.command_id
    AND (
      (
        NEW.outcome = 'enforced' OR
        (NEW.outcome = 'duplicate' AND NEW.original_outcome = 'enforced')
      )
      AND NEW.required_effect_enforcer_set_digest =
        command.required_effect_enforcer_set_digest
      AND NEW.enforcement_subject_digest IS NOT NULL
      AND NEW.aggregate_proof_digest IS NOT NULL
      AND NEW.proof_verified_at_ms IS NOT NULL
      AND NEW.proof_verified_at_ms <= NEW.received_at_ms
      AND COALESCE(
        json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.aggregateEnforcementProof.generation'
            ELSE '$.aggregateEnforcementProof.generation'
          END
        ) = NEW.runtime_authorization_generation,
        0
      )
      AND COALESCE(
        json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.aggregateEnforcementProof.requiredEffectEnforcerSetDigest'
            ELSE '$.aggregateEnforcementProof.requiredEffectEnforcerSetDigest'
          END
        ) = NEW.required_effect_enforcer_set_digest,
        0
      )
      AND COALESCE(
        json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.aggregateEnforcementProof.enforcementSubjectDigest'
            ELSE '$.aggregateEnforcementProof.enforcementSubjectDigest'
          END
        ) = NEW.enforcement_subject_digest,
        0
      )
      AND COALESCE(
        json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.aggregateEnforcementProof.aggregateProofDigest'
            ELSE '$.aggregateEnforcementProof.aggregateProofDigest'
          END
        ) = NEW.aggregate_proof_digest,
        0
      )
    ) OR (
      NOT (
        NEW.outcome = 'enforced' OR
        (NEW.outcome = 'duplicate' AND NEW.original_outcome = 'enforced')
      )
      AND NEW.required_effect_enforcer_set_digest IS NULL
      AND NEW.enforcement_subject_digest IS NULL
      AND NEW.aggregate_proof_digest IS NULL
      AND NEW.proof_verified_at_ms IS NULL
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime enforced receipt lacks an exact verified aggregate proof');
END;

DROP TRIGGER runtime_run_command_effects_enforced_receipt;

CREATE TRIGGER runtime_run_command_effects_enforced_receipt
BEFORE INSERT ON runtime_run_command_effects
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_run_command_receipts receipt
  JOIN runtime_run_commands command ON command.id = receipt.command_id
  WHERE receipt.id = NEW.receipt_id
    AND receipt.command_id = NEW.command_id
    AND (
      receipt.outcome = 'enforced' OR
      (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced')
    )
    AND receipt.required_effect_enforcer_set_digest =
      command.required_effect_enforcer_set_digest
    AND receipt.enforcement_subject_digest IS NOT NULL
    AND receipt.aggregate_proof_digest IS NOT NULL
    AND receipt.proof_verified_at_ms IS NOT NULL
    AND receipt.proof_verified_at_ms <= receipt.received_at_ms
    AND receipt.received_at_ms <= NEW.applied_at_ms
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run effect requires a verified enforced receipt');
END;

CREATE TABLE runtime_principal_observation_keys (
  runtime_assignment_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL CHECK (length(sandbox_id) BETWEEN 1 AND 300),
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL CHECK (length(runtime_principal_id) BETWEEN 1 AND 300),
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  issuer_key_id TEXT NOT NULL CHECK (length(issuer_key_id) BETWEEN 1 AND 300),
  public_key_spki_pem TEXT NOT NULL CHECK (length(public_key_spki_pem) BETWEEN 80 AND 4000),
  public_key_spki_digest TEXT NOT NULL CHECK (
    length(public_key_spki_digest) = 64 AND public_key_spki_digest = lower(public_key_spki_digest)
  ),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  PRIMARY KEY (runtime_assignment_id, runtime_authorization_generation),
  UNIQUE (runtime_assignment_id, runtime_authorization_generation, issuer_key_id),
  UNIQUE (
    runtime_assignment_id, runtime_authorization_generation, issuer_key_id,
    public_key_spki_digest
  ),
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    session_id, runtime_authorization_generation, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_authorization_epochs(
    session_id, generation, runtime_assignment_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER runtime_principal_observation_keys_immutable_update
BEFORE UPDATE ON runtime_principal_observation_keys
BEGIN
  SELECT RAISE(ABORT, 'Runtime principal observation keys are immutable');
END;

CREATE TRIGGER runtime_principal_observation_keys_immutable_delete
BEFORE DELETE ON runtime_principal_observation_keys
BEGIN
  SELECT RAISE(ABORT, 'Runtime principal observation keys are immutable');
END;

CREATE TRIGGER hosted_runtime_observation_identity_unique_insert
BEFORE INSERT ON runtime_principal_observation_keys
WHEN EXISTS (
  SELECT 1
  FROM runtime_assignments desired
  JOIN runtime_principal_observation_keys existing
    ON existing.runtime_assignment_id <> NEW.runtime_assignment_id
   AND (
     existing.issuer_key_id = NEW.issuer_key_id OR
     existing.public_key_spki_digest = NEW.public_key_spki_digest
   )
  WHERE desired.id = NEW.runtime_assignment_id AND desired.runtime_kind = 'daytona'
)
BEGIN
  SELECT RAISE(ABORT, 'Hosted Runtime observation identity is already assigned');
END;

CREATE TABLE runtime_receipt_follow_streams (
  runtime_assignment_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL CHECK (length(sandbox_id) BETWEEN 1 AND 300),
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL CHECK (length(runtime_principal_id) BETWEEN 1 AND 300),
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  issuer_key_id TEXT NOT NULL CHECK (length(issuer_key_id) BETWEEN 1 AND 300),
  public_key_spki_digest TEXT NOT NULL CHECK (
    length(public_key_spki_digest) = 64 AND public_key_spki_digest = lower(public_key_spki_digest)
  ),
  status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'quarantined')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  lease_version INTEGER NOT NULL DEFAULT 0 CHECK (lease_version >= 0),
  available_at_ms INTEGER NOT NULL CHECK (available_at_ms >= created_at_ms),
  lease_owner TEXT,
  lease_expires_at_ms INTEGER,
  cursor TEXT CHECK (
    cursor IS NULL OR length(cursor) BETWEEN 1 AND ${RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS}
  ),
  last_observation_digest TEXT CHECK (
    last_observation_digest IS NULL OR (
      length(last_observation_digest) = 64 AND
      last_observation_digest = lower(last_observation_digest)
    )
  ),
  receipt_sequence INTEGER NOT NULL DEFAULT 0 CHECK (receipt_sequence >= 0),
  last_safe_error_code TEXT CHECK (
    last_safe_error_code IS NULL OR length(last_safe_error_code) BETWEEN 1 AND 200
  ),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
  PRIMARY KEY (runtime_assignment_id, runtime_authorization_generation),
  UNIQUE (
    runtime_assignment_id, runtime_authorization_generation, session_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id,
    issuer_key_id, public_key_spki_digest
  ),
  CHECK (
    (status = 'processing'
      AND lease_owner IS NOT NULL AND length(lease_owner) BETWEEN 1 AND 300
      AND lease_expires_at_ms IS NOT NULL AND lease_expires_at_ms > updated_at_ms) OR
    (status <> 'processing' AND lease_owner IS NULL AND lease_expires_at_ms IS NULL)
  ),
  CHECK (
    (receipt_sequence = 0 AND cursor IS NULL AND last_observation_digest IS NULL) OR
    (receipt_sequence > 0 AND cursor IS NOT NULL AND last_observation_digest IS NOT NULL)
  ),
  FOREIGN KEY (
    runtime_assignment_id, runtime_authorization_generation, issuer_key_id,
    public_key_spki_digest
  ) REFERENCES runtime_principal_observation_keys(
    runtime_assignment_id, runtime_authorization_generation, issuer_key_id,
    public_key_spki_digest
  ) ON DELETE RESTRICT
) STRICT;

CREATE INDEX runtime_receipt_follow_streams_claimable
  ON runtime_receipt_follow_streams(status, available_at_ms, created_at_ms, runtime_assignment_id);

CREATE TRIGGER runtime_receipt_follow_streams_initial_state
BEFORE INSERT ON runtime_receipt_follow_streams
WHEN NEW.status <> 'pending' OR NEW.attempts <> 0 OR NEW.lease_version <> 0 OR
  NEW.available_at_ms <> NEW.created_at_ms OR NEW.lease_owner IS NOT NULL OR
  NEW.lease_expires_at_ms IS NOT NULL OR NEW.cursor IS NOT NULL OR
  NEW.last_observation_digest IS NOT NULL OR NEW.receipt_sequence <> 0 OR
  NEW.last_safe_error_code IS NOT NULL OR NEW.updated_at_ms <> NEW.created_at_ms
BEGIN
  SELECT RAISE(ABORT, 'Runtime receipt follow stream must begin pending');
END;

CREATE TRIGGER runtime_receipt_follow_streams_identity_immutable
BEFORE UPDATE OF
  runtime_assignment_id, session_id, runtime_assignment_generation, sandbox_id,
  sandbox_generation, runtime_principal_id, runtime_authorization_generation,
  issuer_key_id, public_key_spki_digest, created_at_ms
ON runtime_receipt_follow_streams
BEGIN
  SELECT RAISE(ABORT, 'Runtime receipt follow stream identity is immutable');
END;

CREATE TRIGGER runtime_receipt_follow_streams_immutable_delete
BEFORE DELETE ON runtime_receipt_follow_streams
BEGIN
  SELECT RAISE(ABORT, 'Runtime receipt follow streams cannot be deleted');
END;

CREATE TABLE runtime_receipt_follow_events (
  id TEXT PRIMARY KEY,
  runtime_assignment_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL CHECK (length(sandbox_id) BETWEEN 1 AND 300),
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL CHECK (length(runtime_principal_id) BETWEEN 1 AND 300),
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  issuer_key_id TEXT NOT NULL CHECK (length(issuer_key_id) BETWEEN 1 AND 300),
  public_key_spki_digest TEXT NOT NULL CHECK (
    length(public_key_spki_digest) = 64 AND public_key_spki_digest = lower(public_key_spki_digest)
  ),
  receipt_sequence INTEGER NOT NULL CHECK (receipt_sequence >= 1),
  cursor TEXT NOT NULL CHECK (
    length(cursor) BETWEEN 1 AND ${RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS}
  ),
  previous_cursor TEXT CHECK (
    previous_cursor IS NULL OR
    length(previous_cursor) BETWEEN 1 AND ${RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS}
  ),
  previous_observation_digest TEXT CHECK (
    previous_observation_digest IS NULL OR (
      length(previous_observation_digest) = 64 AND
      previous_observation_digest = lower(previous_observation_digest)
    )
  ),
  observation_digest TEXT NOT NULL CHECK (
    length(observation_digest) = 64 AND observation_digest = lower(observation_digest)
  ),
  command_id TEXT NOT NULL,
  command_digest TEXT NOT NULL CHECK (
    length(command_digest) = 64 AND command_digest = lower(command_digest)
  ),
  receipt_id TEXT NOT NULL,
  wire_receipt_digest TEXT NOT NULL CHECK (
    length(wire_receipt_digest) = 64 AND wire_receipt_digest = lower(wire_receipt_digest)
  ),
  effective_receipt_digest TEXT NOT NULL CHECK (
    length(effective_receipt_digest) = 64 AND
    effective_receipt_digest = lower(effective_receipt_digest)
  ),
  signature TEXT NOT NULL CHECK (length(signature) BETWEEN 1 AND 2000),
  lease_owner TEXT NOT NULL CHECK (length(lease_owner) BETWEEN 1 AND 300),
  lease_version INTEGER NOT NULL CHECK (lease_version >= 1),
  observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
  received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= observed_at_ms),
  UNIQUE (runtime_assignment_id, runtime_authorization_generation, receipt_sequence),
  UNIQUE (runtime_assignment_id, runtime_authorization_generation, cursor),
  UNIQUE (runtime_assignment_id, runtime_authorization_generation, observation_digest),
  FOREIGN KEY (
    runtime_assignment_id, runtime_authorization_generation, session_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id,
    issuer_key_id, public_key_spki_digest
  ) REFERENCES runtime_receipt_follow_streams(
    runtime_assignment_id, runtime_authorization_generation, session_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id,
    issuer_key_id, public_key_spki_digest
  ) ON DELETE RESTRICT,
  FOREIGN KEY (command_id) REFERENCES runtime_run_commands(id) ON DELETE RESTRICT,
  FOREIGN KEY (receipt_id) REFERENCES runtime_run_command_receipts(id) ON DELETE RESTRICT,
  CHECK (
    (receipt_sequence = 1 AND previous_cursor IS NULL AND previous_observation_digest IS NULL) OR
    (receipt_sequence > 1 AND previous_cursor IS NOT NULL AND previous_observation_digest IS NOT NULL)
  )
) STRICT;

CREATE TRIGGER runtime_receipt_follow_events_valid_insert
BEFORE INSERT ON runtime_receipt_follow_events
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_receipt_follow_streams stream
  JOIN runtime_run_commands command ON command.id = NEW.command_id
  JOIN runtime_run_command_receipts receipt ON receipt.id = NEW.receipt_id
  WHERE stream.runtime_assignment_id = NEW.runtime_assignment_id
    AND stream.runtime_authorization_generation = NEW.runtime_authorization_generation
    AND stream.status = 'processing'
    AND stream.lease_owner = NEW.lease_owner
    AND stream.lease_version = NEW.lease_version
    AND stream.lease_expires_at_ms > NEW.received_at_ms
    AND NEW.receipt_sequence = stream.receipt_sequence + 1
    AND NEW.previous_cursor IS stream.cursor
    AND NEW.previous_observation_digest IS stream.last_observation_digest
    AND command.session_id = NEW.session_id
    AND command.runtime_assignment_id = NEW.runtime_assignment_id
    AND command.runtime_assignment_generation = NEW.runtime_assignment_generation
    AND command.sandbox_id = NEW.sandbox_id
    AND command.sandbox_generation = NEW.sandbox_generation
    AND command.runtime_principal_id = NEW.runtime_principal_id
    AND command.runtime_authorization_generation = NEW.runtime_authorization_generation
    AND command.command_digest = NEW.command_digest
    AND receipt.command_id = NEW.command_id
    AND receipt.receipt_digest = NEW.effective_receipt_digest
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime receipt follow event is not exact-bound to its lease and receipt');
END;

CREATE TRIGGER runtime_receipt_follow_events_immutable_update
BEFORE UPDATE ON runtime_receipt_follow_events
BEGIN
  SELECT RAISE(ABORT, 'Runtime receipt follow events are immutable');
END;

CREATE TRIGGER runtime_receipt_follow_events_immutable_delete
BEFORE DELETE ON runtime_receipt_follow_events
BEGIN
  SELECT RAISE(ABORT, 'Runtime receipt follow events cannot be deleted');
END;

CREATE TRIGGER runtime_receipt_follow_streams_valid_transition
BEFORE UPDATE ON runtime_receipt_follow_streams
WHEN NEW.updated_at_ms < OLD.updated_at_ms OR NOT (
  (OLD.status = 'pending' AND NEW.status = 'processing'
    AND NEW.attempts = OLD.attempts + 1
    AND NEW.lease_version = OLD.lease_version + 1
    AND NEW.available_at_ms = OLD.available_at_ms
    AND NEW.cursor IS OLD.cursor
    AND NEW.last_observation_digest IS OLD.last_observation_digest
    AND NEW.receipt_sequence = OLD.receipt_sequence
    AND NEW.updated_at_ms >= OLD.available_at_ms) OR
  (OLD.status = 'pending' AND NEW.status = 'pending'
    AND NEW.attempts = OLD.attempts
    AND NEW.lease_version = OLD.lease_version
    AND NEW.available_at_ms >= OLD.available_at_ms
    AND NEW.available_at_ms >= NEW.updated_at_ms
    AND NEW.cursor IS OLD.cursor
    AND NEW.last_observation_digest IS OLD.last_observation_digest
    AND NEW.receipt_sequence = OLD.receipt_sequence) OR
  (OLD.status = 'processing' AND NEW.status = 'processing'
    AND NEW.attempts = OLD.attempts
    AND NEW.lease_version = OLD.lease_version
    AND NEW.available_at_ms = OLD.available_at_ms
    AND NEW.lease_owner = OLD.lease_owner
    AND NEW.cursor IS OLD.cursor
    AND NEW.last_observation_digest IS OLD.last_observation_digest
    AND NEW.receipt_sequence = OLD.receipt_sequence
    AND NEW.updated_at_ms < OLD.lease_expires_at_ms
    AND NEW.lease_expires_at_ms >= OLD.lease_expires_at_ms) OR
  (OLD.status = 'processing' AND NEW.status = 'pending'
    AND NEW.attempts = OLD.attempts
    AND NEW.lease_version = OLD.lease_version
    AND NEW.available_at_ms >= OLD.available_at_ms
    AND NEW.available_at_ms >= NEW.updated_at_ms
    AND (
      (NEW.cursor IS OLD.cursor
        AND NEW.last_observation_digest IS OLD.last_observation_digest
        AND NEW.receipt_sequence = OLD.receipt_sequence) OR
      (NEW.cursor IS NOT NULL
        AND NEW.last_observation_digest IS NOT NULL
        AND NEW.receipt_sequence = OLD.receipt_sequence + 1
        AND EXISTS (
          SELECT 1 FROM runtime_receipt_follow_events event
          WHERE event.runtime_assignment_id = OLD.runtime_assignment_id
            AND event.runtime_authorization_generation = OLD.runtime_authorization_generation
            AND event.receipt_sequence = NEW.receipt_sequence
            AND event.cursor = NEW.cursor
            AND event.observation_digest = NEW.last_observation_digest
            AND event.lease_owner = OLD.lease_owner
            AND event.lease_version = OLD.lease_version
        ))
    )) OR
  (OLD.status IN ('pending', 'processing') AND NEW.status = 'quarantined'
    AND NEW.attempts = OLD.attempts
    AND NEW.lease_version = OLD.lease_version
    AND NEW.available_at_ms = OLD.available_at_ms
    AND NEW.cursor IS OLD.cursor
    AND NEW.last_observation_digest IS OLD.last_observation_digest
    AND NEW.receipt_sequence = OLD.receipt_sequence
    AND NEW.last_safe_error_code IS NOT NULL) OR
  (OLD.status = 'quarantined' AND NEW.status = 'quarantined'
    AND NEW.attempts = OLD.attempts
    AND NEW.lease_version = OLD.lease_version
    AND NEW.available_at_ms = OLD.available_at_ms
    AND NEW.cursor IS OLD.cursor
    AND NEW.last_observation_digest IS OLD.last_observation_digest
    AND NEW.receipt_sequence = OLD.receipt_sequence
    AND NEW.last_safe_error_code = OLD.last_safe_error_code)
)
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime receipt follow stream transition');
END;
`;

const RUNTIME_COMPENSATION_TABLES_SCHEMA_V7 = `
CREATE TABLE runtime_binding_safety_fences (
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  allocated_fence INTEGER NOT NULL CHECK (
    allocated_fence >= 1 AND allocated_fence <= 9007199254740991
  ),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
  PRIMARY KEY (
    team_id, project_id, session_id, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id
  ),
  FOREIGN KEY (session_id, team_id, project_id)
    REFERENCES sessions(id, team_id, project_id) ON DELETE RESTRICT,
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE runtime_compensation_incidents (
  compensation_id TEXT PRIMARY KEY CHECK (length(compensation_id) BETWEEN 1 AND 300),
  incident_digest TEXT NOT NULL UNIQUE CHECK (
    length(incident_digest) = 64 AND incident_digest NOT GLOB '*[^0-9a-f]*'
  ),
  source_command_id TEXT NOT NULL UNIQUE,
  source_receipt_id TEXT NOT NULL UNIQUE,
  trust_state TEXT NOT NULL CHECK (trust_state IN ('verified', 'legacy-untrusted')),
  session_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  run_policy_revision INTEGER NOT NULL CHECK (run_policy_revision >= 1),
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  source_command_digest TEXT NOT NULL CHECK (
    length(source_command_digest) = 64 AND source_command_digest = lower(source_command_digest)
  ),
  lifecycle_command_claims_digest TEXT NOT NULL CHECK (
    length(lifecycle_command_claims_digest) = 64 AND
    lifecycle_command_claims_digest NOT GLOB '*[^0-9a-f]*'
  ),
  lifecycle_receipt_digest TEXT NOT NULL CHECK (
    length(lifecycle_receipt_digest) = 64 AND
    lifecycle_receipt_digest NOT GLOB '*[^0-9a-f]*'
  ),
  source_enforced_fence INTEGER NOT NULL CHECK (
    source_enforced_fence >= 1 AND source_enforced_fence <= 9007199254740991
  ),
  safety_fence INTEGER NOT NULL CHECK (
    safety_fence > source_enforced_fence AND safety_fence <= 9007199254740991
  ),
  source_effect_ref_commitment TEXT,
  source_required_effect_enforcer_set_digest TEXT,
  lifecycle_enforcement_subject_digest TEXT,
  lifecycle_aggregate_proof_digest TEXT,
  source_proof_verified_at_ms INTEGER,
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  UNIQUE (
    compensation_id, source_command_id, source_receipt_id,
    session_id, team_id, project_id, agent_run_id,
    runtime_assignment_id, runtime_assignment_generation, sandbox_id,
    sandbox_generation, runtime_principal_id, runtime_authorization_generation
  ),
  UNIQUE (compensation_id, source_command_id),
  UNIQUE (
    team_id, project_id, session_id, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, safety_fence
  ),
  CHECK (
    (trust_state = 'verified'
      AND source_effect_ref_commitment IS NOT NULL
      AND length(source_effect_ref_commitment) = 74
      AND substr(source_effect_ref_commitment, 1, 10) = 'effect:v1:'
      AND substr(source_effect_ref_commitment, 11) NOT GLOB '*[^0-9a-f]*'
      AND source_required_effect_enforcer_set_digest IS NOT NULL
      AND length(source_required_effect_enforcer_set_digest) = 64
      AND source_required_effect_enforcer_set_digest NOT GLOB '*[^0-9a-f]*'
      AND lifecycle_enforcement_subject_digest IS NOT NULL
      AND length(lifecycle_enforcement_subject_digest) = 64
      AND lifecycle_enforcement_subject_digest NOT GLOB '*[^0-9a-f]*'
      AND lifecycle_aggregate_proof_digest IS NOT NULL
      AND length(lifecycle_aggregate_proof_digest) = 64
      AND lifecycle_aggregate_proof_digest NOT GLOB '*[^0-9a-f]*'
      AND source_proof_verified_at_ms IS NOT NULL
      AND source_proof_verified_at_ms >= 0) OR
    (trust_state = 'legacy-untrusted'
      AND source_effect_ref_commitment IS NULL
      AND source_required_effect_enforcer_set_digest IS NULL
      AND lifecycle_enforcement_subject_digest IS NULL
      AND lifecycle_aggregate_proof_digest IS NULL
      AND source_proof_verified_at_ms IS NULL)
  ),
  FOREIGN KEY (source_command_id) REFERENCES runtime_run_commands(id) ON DELETE RESTRICT,
  FOREIGN KEY (source_receipt_id) REFERENCES runtime_run_command_receipts(id) ON DELETE RESTRICT,
  FOREIGN KEY (session_id, team_id, project_id)
    REFERENCES sessions(id, team_id, project_id) ON DELETE RESTRICT,
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    session_id, runtime_authorization_generation, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_authorization_epochs(
    session_id, generation, runtime_assignment_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE runtime_compensation_commands (
  id TEXT PRIMARY KEY,
  compensation_id TEXT NOT NULL,
  source_command_id TEXT NOT NULL,
  command_sequence INTEGER NOT NULL CHECK (command_sequence >= 1),
  previous_command_sequence INTEGER,
  operation TEXT NOT NULL CHECK (operation = 'safety.quarantine'),
  session_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  observed_runtime_authorization_generation INTEGER NOT NULL
    CHECK (observed_runtime_authorization_generation >= 1),
  source_required_effect_enforcer_set_digest TEXT NOT NULL CHECK (
    length(source_required_effect_enforcer_set_digest) = 64 AND
    source_required_effect_enforcer_set_digest NOT GLOB '*[^0-9a-f]*'
  ),
  lifecycle_command_claims_digest TEXT NOT NULL CHECK (
    length(lifecycle_command_claims_digest) = 64 AND
    lifecycle_command_claims_digest NOT GLOB '*[^0-9a-f]*'
  ),
  lifecycle_receipt_digest TEXT NOT NULL CHECK (
    length(lifecycle_receipt_digest) = 64 AND
    lifecycle_receipt_digest NOT GLOB '*[^0-9a-f]*'
  ),
  lifecycle_enforcement_subject_digest TEXT NOT NULL CHECK (
    length(lifecycle_enforcement_subject_digest) = 64 AND
    lifecycle_enforcement_subject_digest NOT GLOB '*[^0-9a-f]*'
  ),
  lifecycle_aggregate_proof_digest TEXT NOT NULL CHECK (
    length(lifecycle_aggregate_proof_digest) = 64 AND
    lifecycle_aggregate_proof_digest NOT GLOB '*[^0-9a-f]*'
  ),
  platform_security_policy_revision TEXT NOT NULL
    CHECK (length(platform_security_policy_revision) BETWEEN 1 AND 300),
  required_containment_enforcer_set_digest TEXT NOT NULL CHECK (
    length(required_containment_enforcer_set_digest) = 64 AND
    required_containment_enforcer_set_digest NOT GLOB '*[^0-9a-f]*'
  ),
  safety_fence INTEGER NOT NULL CHECK (
    safety_fence >= 1 AND safety_fence <= 9007199254740991
  ),
  reason_ref TEXT NOT NULL CHECK (length(reason_ref) BETWEEN 1 AND 300),
  causation_id TEXT NOT NULL CHECK (length(causation_id) BETWEEN 1 AND 300),
  command_json TEXT NOT NULL CHECK (
    json_valid(command_json) AND json_type(command_json) = 'object'
  ),
  command_digest TEXT NOT NULL CHECK (
    length(command_digest) = 64 AND command_digest = lower(command_digest)
  ),
  authority_digest TEXT NOT NULL CHECK (
    length(authority_digest) = 64 AND authority_digest = lower(authority_digest)
  ),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  authority_verified_at_ms INTEGER NOT NULL CHECK (
    authority_verified_at_ms >= created_at_ms
  ),
  deadline_at_ms INTEGER NOT NULL CHECK (deadline_at_ms > created_at_ms),
  CHECK (authority_verified_at_ms < deadline_at_ms),
  UNIQUE (compensation_id, command_sequence),
  UNIQUE (id, compensation_id, source_command_id),
  CHECK (
    (command_sequence = 1 AND previous_command_sequence IS NULL) OR
    (command_sequence > 1 AND previous_command_sequence = command_sequence - 1)
  ),
  FOREIGN KEY (compensation_id, source_command_id)
    REFERENCES runtime_compensation_incidents(compensation_id, source_command_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (compensation_id, previous_command_sequence)
    REFERENCES runtime_compensation_commands(compensation_id, command_sequence)
    ON DELETE RESTRICT,
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT,
  FOREIGN KEY (
    session_id, observed_runtime_authorization_generation, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_authorization_epochs(
    session_id, generation, runtime_assignment_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE runtime_compensation_dispatch (
  compensation_command_id TEXT PRIMARY KEY,
  compensation_id TEXT NOT NULL,
  source_command_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'pending', 'processing', 'awaiting-receipt',
    'enforced', 'blocked', 'expired-before-dispatch'
  )),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  available_at_ms INTEGER NOT NULL CHECK (available_at_ms >= created_at_ms),
  lease_owner TEXT,
  lease_expires_at_ms INTEGER,
  dispatch_interlock_acquired_at_ms INTEGER CHECK (
    dispatch_interlock_acquired_at_ms IS NULL OR
    dispatch_interlock_acquired_at_ms >= created_at_ms
  ),
  last_safe_error_code TEXT CHECK (
    last_safe_error_code IS NULL OR length(last_safe_error_code) BETWEEN 1 AND 200
  ),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
  terminal_at_ms INTEGER,
  CHECK (
    (status = 'processing'
      AND lease_owner IS NOT NULL AND length(lease_owner) BETWEEN 1 AND 300
      AND lease_expires_at_ms IS NOT NULL AND lease_expires_at_ms > updated_at_ms) OR
    (status <> 'processing' AND lease_owner IS NULL AND lease_expires_at_ms IS NULL)
  ),
  CHECK (
    (status IN ('enforced', 'blocked', 'expired-before-dispatch')
      AND terminal_at_ms IS NOT NULL AND terminal_at_ms >= created_at_ms) OR
    (status IN ('pending', 'processing', 'awaiting-receipt') AND terminal_at_ms IS NULL)
  ),
  UNIQUE (compensation_command_id, compensation_id, source_command_id),
  FOREIGN KEY (compensation_command_id, compensation_id, source_command_id)
    REFERENCES runtime_compensation_commands(id, compensation_id, source_command_id)
    ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX one_unresolved_runtime_compensation_per_case
  ON runtime_compensation_dispatch(compensation_id)
  WHERE status IN ('pending', 'processing', 'awaiting-receipt');

CREATE INDEX runtime_compensation_dispatch_claimable
  ON runtime_compensation_dispatch(status, available_at_ms, created_at_ms, compensation_command_id);

CREATE TABLE runtime_compensation_receipts (
  id TEXT PRIMARY KEY,
  compensation_command_id TEXT NOT NULL,
  compensation_id TEXT NOT NULL,
  source_command_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  previous_version INTEGER,
  session_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  observed_runtime_authorization_generation INTEGER NOT NULL
    CHECK (observed_runtime_authorization_generation >= 1),
  command_digest TEXT NOT NULL CHECK (
    length(command_digest) = 64 AND command_digest = lower(command_digest)
  ),
  enforced_safety_fence INTEGER CHECK (
    enforced_safety_fence IS NULL OR (
      enforced_safety_fence >= 1 AND enforced_safety_fence <= 9007199254740991
    )
  ),
  outcome TEXT NOT NULL CHECK (outcome IN (
    'accepted', 'enforced', 'duplicate', 'rejected', 'quarantined'
  )),
  original_outcome TEXT CHECK (
    original_outcome IS NULL OR original_outcome IN (
      'accepted', 'enforced', 'rejected', 'quarantined'
    )
  ),
  original_receipt_digest TEXT CHECK (
    original_receipt_digest IS NULL OR (
      length(original_receipt_digest) = 64 AND
      original_receipt_digest = lower(original_receipt_digest)
    )
  ),
  receipt_json TEXT NOT NULL CHECK (
    json_valid(receipt_json) AND json_type(receipt_json) = 'object'
    AND COALESCE(json_extract(receipt_json, '$.receiptKind') = 'runtime.compensation', 0)
    AND COALESCE(json_extract(receipt_json, '$.compensationId') = compensation_id, 0)
    AND COALESCE(json_extract(receipt_json, '$.commandId') = compensation_command_id, 0)
    AND COALESCE(json_extract(receipt_json, '$.outcome') = outcome, 0)
    AND COALESCE(
      json_extract(receipt_json, '$.observedRuntimeAuthorizationGeneration') =
        observed_runtime_authorization_generation,
      0
    )
    AND COALESCE(json_extract(receipt_json, '$.binding.teamId') = team_id, 0)
    AND COALESCE(json_extract(receipt_json, '$.binding.projectId') = project_id, 0)
    AND COALESCE(json_extract(receipt_json, '$.binding.sessionId') = session_id, 0)
    AND COALESCE(
      json_extract(receipt_json, '$.binding.runtimeAssignmentId') = runtime_assignment_id,
      0
    )
    AND COALESCE(
      json_extract(receipt_json, '$.binding.runtimeAssignmentGeneration') =
        runtime_assignment_generation,
      0
    )
    AND COALESCE(json_extract(receipt_json, '$.binding.sandboxId') = sandbox_id, 0)
    AND COALESCE(
      json_extract(receipt_json, '$.binding.sandboxGeneration') = sandbox_generation,
      0
    )
    AND COALESCE(
      json_extract(receipt_json, '$.binding.runtimePrincipalId') = runtime_principal_id,
      0
    )
    AND (
      outcome <> 'duplicate' OR COALESCE(
        json_type(receipt_json, '$.originalReceipt') = 'object'
          AND json_extract(
            receipt_json, '$.originalReceipt.receiptKind'
          ) = 'runtime.compensation'
          AND json_extract(
            receipt_json, '$.originalReceipt.compensationId'
          ) = compensation_id
          AND json_extract(
            receipt_json, '$.originalReceipt.commandId'
          ) = compensation_command_id
          AND json_extract(
            receipt_json, '$.originalReceipt.outcome'
          ) = original_outcome
          AND json_extract(
            receipt_json, '$.originalReceiptDigest'
          ) = original_receipt_digest
          AND json_extract(
            receipt_json, '$.originalReceipt.observedRuntimeAuthorizationGeneration'
          ) = observed_runtime_authorization_generation
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.teamId'
          ) = team_id
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.projectId'
          ) = project_id
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.sessionId'
          ) = session_id
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.runtimeAssignmentId'
          ) = runtime_assignment_id
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.runtimeAssignmentGeneration'
          ) = runtime_assignment_generation
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.sandboxId'
          ) = sandbox_id
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.sandboxGeneration'
          ) = sandbox_generation
          AND json_extract(
            receipt_json, '$.originalReceipt.binding.runtimePrincipalId'
          ) = runtime_principal_id,
        0
      )
    )
  ),
  receipt_digest TEXT NOT NULL CHECK (
    length(receipt_digest) = 64 AND receipt_digest = lower(receipt_digest)
  ),
  required_containment_enforcer_set_digest TEXT,
  effect_ref_commitment TEXT,
  enforcement_subject_digest TEXT,
  aggregate_proof_digest TEXT,
  proof_verified_at_ms INTEGER CHECK (proof_verified_at_ms IS NULL OR proof_verified_at_ms >= 0),
  received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= 0),
  UNIQUE (compensation_command_id, version),
  UNIQUE (compensation_command_id, receipt_digest),
  UNIQUE (id, compensation_command_id),
  UNIQUE (id, compensation_command_id, outcome),
  CHECK (
    (version = 1 AND previous_version IS NULL) OR
    (version > 1 AND previous_version = version - 1)
  ),
  CHECK (
    (outcome = 'duplicate' AND original_outcome IS NOT NULL
      AND original_receipt_digest IS NOT NULL) OR
    (outcome <> 'duplicate' AND original_outcome IS NULL
      AND original_receipt_digest IS NULL)
  ),
  FOREIGN KEY (compensation_command_id, compensation_id, source_command_id)
    REFERENCES runtime_compensation_commands(id, compensation_id, source_command_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (compensation_command_id, previous_version)
    REFERENCES runtime_compensation_receipts(compensation_command_id, version)
    ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX one_terminal_runtime_compensation_receipt_per_command
  ON runtime_compensation_receipts(compensation_command_id)
  WHERE outcome IN ('enforced', 'rejected', 'quarantined');

CREATE TABLE runtime_compensation_effects (
  compensation_id TEXT PRIMARY KEY,
  source_command_id TEXT NOT NULL UNIQUE,
  compensation_command_id TEXT NOT NULL UNIQUE,
  receipt_id TEXT NOT NULL UNIQUE,
  receipt_outcome TEXT NOT NULL CHECK (receipt_outcome IN ('enforced', 'duplicate')),
  session_id TEXT NOT NULL,
  agent_run_id TEXT NOT NULL,
  applied_session_sequence INTEGER NOT NULL CHECK (applied_session_sequence >= 1),
  effect_digest TEXT NOT NULL UNIQUE CHECK (
    length(effect_digest) = 64 AND effect_digest = lower(effect_digest)
  ),
  applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0),
  FOREIGN KEY (compensation_id, source_command_id)
    REFERENCES runtime_compensation_incidents(compensation_id, source_command_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (compensation_command_id, compensation_id, source_command_id)
    REFERENCES runtime_compensation_commands(id, compensation_id, source_command_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (receipt_id, compensation_command_id, receipt_outcome)
    REFERENCES runtime_compensation_receipts(id, compensation_command_id, outcome)
    ON DELETE RESTRICT,
  FOREIGN KEY (session_id, applied_session_sequence)
    REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
) STRICT;

CREATE TABLE runtime_compensation_follow_events (
  id TEXT PRIMARY KEY,
  runtime_assignment_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  runtime_authorization_generation INTEGER NOT NULL
    CHECK (runtime_authorization_generation >= 1),
  issuer_key_id TEXT NOT NULL CHECK (length(issuer_key_id) BETWEEN 1 AND 300),
  public_key_spki_digest TEXT NOT NULL CHECK (
    length(public_key_spki_digest) = 64 AND public_key_spki_digest = lower(public_key_spki_digest)
  ),
  receipt_sequence INTEGER NOT NULL CHECK (receipt_sequence >= 1),
  cursor TEXT NOT NULL CHECK (
    length(cursor) BETWEEN 1 AND ${RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS}
  ),
  previous_cursor TEXT CHECK (
    previous_cursor IS NULL OR
    length(previous_cursor) BETWEEN 1 AND ${RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS}
  ),
  previous_observation_digest TEXT CHECK (
    previous_observation_digest IS NULL OR (
      length(previous_observation_digest) = 64 AND
      previous_observation_digest = lower(previous_observation_digest)
    )
  ),
  observation_digest TEXT NOT NULL CHECK (
    length(observation_digest) = 64 AND observation_digest = lower(observation_digest)
  ),
  compensation_command_id TEXT NOT NULL,
  compensation_id TEXT NOT NULL,
  source_command_id TEXT NOT NULL,
  command_digest TEXT NOT NULL CHECK (
    length(command_digest) = 64 AND command_digest = lower(command_digest)
  ),
  receipt_id TEXT NOT NULL,
  wire_receipt_digest TEXT NOT NULL CHECK (
    length(wire_receipt_digest) = 64 AND wire_receipt_digest = lower(wire_receipt_digest)
  ),
  effective_receipt_digest TEXT NOT NULL CHECK (
    length(effective_receipt_digest) = 64 AND
    effective_receipt_digest = lower(effective_receipt_digest)
  ),
  signature TEXT NOT NULL CHECK (length(signature) BETWEEN 1 AND 2000),
  lease_owner TEXT NOT NULL CHECK (length(lease_owner) BETWEEN 1 AND 300),
  lease_version INTEGER NOT NULL CHECK (lease_version >= 1),
  observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
  received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= observed_at_ms),
  UNIQUE (runtime_assignment_id, runtime_authorization_generation, receipt_sequence),
  UNIQUE (runtime_assignment_id, runtime_authorization_generation, cursor),
  UNIQUE (runtime_assignment_id, runtime_authorization_generation, observation_digest),
  FOREIGN KEY (
    runtime_assignment_id, runtime_authorization_generation, session_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id,
    issuer_key_id, public_key_spki_digest
  ) REFERENCES runtime_receipt_follow_streams(
    runtime_assignment_id, runtime_authorization_generation, session_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id,
    issuer_key_id, public_key_spki_digest
  ) ON DELETE RESTRICT,
  FOREIGN KEY (compensation_command_id, compensation_id, source_command_id)
    REFERENCES runtime_compensation_commands(id, compensation_id, source_command_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (receipt_id, compensation_command_id)
    REFERENCES runtime_compensation_receipts(id, compensation_command_id) ON DELETE RESTRICT,
  CHECK (
    (receipt_sequence = 1 AND previous_cursor IS NULL AND previous_observation_digest IS NULL) OR
    (receipt_sequence > 1 AND previous_cursor IS NOT NULL AND previous_observation_digest IS NOT NULL)
  )
) STRICT;
`;

const RUNTIME_COMPENSATION_TRIGGERS_SCHEMA_V7 = `
CREATE TRIGGER runtime_assignments_create_binding_safety_fence
AFTER INSERT ON runtime_assignments
BEGIN
  INSERT INTO runtime_binding_safety_fences (
    team_id, project_id, session_id, runtime_assignment_id,
    runtime_assignment_generation, sandbox_id, sandbox_generation,
    runtime_principal_id, allocated_fence, updated_at_ms
  )
  SELECT
    NEW.team_id, NEW.project_id, NEW.session_id, NEW.id,
    NEW.generation, NEW.sandbox_id, NEW.sandbox_generation,
    NEW.runtime_principal_id,
    MAX(1, session.control_epoch, session.steering_revision,
      session.runtime_authorization_generation),
    NEW.created_at_ms
  FROM sessions session
  WHERE session.id = NEW.session_id;
END;

CREATE TRIGGER runtime_binding_safety_fences_valid_insert
BEFORE INSERT ON runtime_binding_safety_fences
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_assignments assignment
  JOIN sessions session ON session.id = assignment.session_id
  WHERE assignment.id = NEW.runtime_assignment_id
    AND assignment.session_id = NEW.session_id
    AND assignment.team_id = NEW.team_id
    AND assignment.project_id = NEW.project_id
    AND assignment.generation = NEW.runtime_assignment_generation
    AND assignment.sandbox_id = NEW.sandbox_id
    AND assignment.sandbox_generation = NEW.sandbox_generation
    AND assignment.runtime_principal_id = NEW.runtime_principal_id
    AND NEW.allocated_fence >= session.control_epoch
    AND NEW.allocated_fence >= session.steering_revision
    AND NEW.allocated_fence >= session.runtime_authorization_generation
    AND NEW.allocated_fence >= COALESCE((
      SELECT MAX(run.state_version)
      FROM agent_runs run
      WHERE run.session_id = NEW.session_id
        AND run.runtime_assignment_id = NEW.runtime_assignment_id
    ), 1)
    AND NEW.allocated_fence >= COALESCE((
      SELECT MAX(command.target_run_state_version)
      FROM runtime_run_commands command
      WHERE command.session_id = NEW.session_id
        AND command.runtime_assignment_id = NEW.runtime_assignment_id
        AND command.runtime_assignment_generation = NEW.runtime_assignment_generation
        AND command.sandbox_id = NEW.sandbox_id
        AND command.sandbox_generation = NEW.sandbox_generation
        AND command.runtime_principal_id = NEW.runtime_principal_id
    ), 1)
    AND NEW.allocated_fence >= COALESCE((
      SELECT MAX(json_extract(
        receipt.receipt_json,
        CASE WHEN receipt.outcome = 'duplicate'
          THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
      ))
      FROM runtime_run_command_receipts receipt
      JOIN runtime_run_commands command ON command.id = receipt.command_id
      WHERE command.session_id = NEW.session_id
        AND command.runtime_assignment_id = NEW.runtime_assignment_id
        AND command.runtime_assignment_generation = NEW.runtime_assignment_generation
        AND command.sandbox_id = NEW.sandbox_id
        AND command.sandbox_generation = NEW.sandbox_generation
        AND command.runtime_principal_id = NEW.runtime_principal_id
        AND (receipt.outcome = 'enforced' OR
          (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced'))
    ), 1)
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime binding safety fence starts below durable high-water');
END;

CREATE TRIGGER runtime_binding_safety_fences_identity_immutable
BEFORE UPDATE OF team_id, project_id, session_id, runtime_assignment_id,
  runtime_assignment_generation, sandbox_id, sandbox_generation, runtime_principal_id
ON runtime_binding_safety_fences
BEGIN
  SELECT RAISE(ABORT, 'Runtime binding safety fence identity is immutable');
END;

CREATE TRIGGER runtime_binding_safety_fences_valid_advance
BEFORE UPDATE OF allocated_fence, updated_at_ms ON runtime_binding_safety_fences
WHEN NOT (
  NEW.allocated_fence > OLD.allocated_fence
  AND NEW.updated_at_ms >= OLD.updated_at_ms
  AND EXISTS (
    SELECT 1
    FROM runtime_assignments assignment
    JOIN sessions session ON session.id = assignment.session_id
    WHERE assignment.id = NEW.runtime_assignment_id
      AND assignment.session_id = NEW.session_id
      AND assignment.team_id = NEW.team_id
      AND assignment.project_id = NEW.project_id
      AND assignment.generation = NEW.runtime_assignment_generation
      AND assignment.sandbox_id = NEW.sandbox_id
      AND assignment.sandbox_generation = NEW.sandbox_generation
      AND assignment.runtime_principal_id = NEW.runtime_principal_id
      AND NEW.allocated_fence > session.control_epoch
      AND NEW.allocated_fence > session.steering_revision
      AND NEW.allocated_fence > session.runtime_authorization_generation
      AND NEW.allocated_fence > COALESCE((
        SELECT MAX(run.state_version)
        FROM agent_runs run
        WHERE run.session_id = NEW.session_id
          AND run.runtime_assignment_id = NEW.runtime_assignment_id
      ), 0)
      AND NEW.allocated_fence > COALESCE((
        SELECT MAX(command.target_run_state_version)
        FROM runtime_run_commands command
        WHERE command.session_id = NEW.session_id
          AND command.runtime_assignment_id = NEW.runtime_assignment_id
          AND command.runtime_assignment_generation = NEW.runtime_assignment_generation
          AND command.sandbox_id = NEW.sandbox_id
          AND command.sandbox_generation = NEW.sandbox_generation
          AND command.runtime_principal_id = NEW.runtime_principal_id
      ), 0)
      AND NEW.allocated_fence > COALESCE((
        SELECT MAX(json_extract(
          receipt.receipt_json,
          CASE WHEN receipt.outcome = 'duplicate'
            THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
        ))
        FROM runtime_run_command_receipts receipt
        JOIN runtime_run_commands command ON command.id = receipt.command_id
        WHERE command.session_id = NEW.session_id
          AND command.runtime_assignment_id = NEW.runtime_assignment_id
          AND command.runtime_assignment_generation = NEW.runtime_assignment_generation
          AND command.sandbox_id = NEW.sandbox_id
          AND command.sandbox_generation = NEW.sandbox_generation
          AND command.runtime_principal_id = NEW.runtime_principal_id
          AND (receipt.outcome = 'enforced' OR
            (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced'))
          AND json_type(
            receipt.receipt_json,
            CASE WHEN receipt.outcome = 'duplicate'
              THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
          ) = 'integer'
      ), 0)
  )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime binding safety fence must advance beyond durable high-water');
END;

CREATE TRIGGER runtime_binding_safety_fences_immutable_delete
BEFORE DELETE ON runtime_binding_safety_fences
BEGIN
  SELECT RAISE(ABORT, 'Runtime binding safety fences cannot be deleted');
END;

CREATE TRIGGER runtime_compensation_incidents_valid_insert
BEFORE INSERT ON runtime_compensation_incidents
WHEN NEW.trust_state <> 'verified' OR NOT EXISTS (
  SELECT 1
  FROM runtime_run_commands command
  JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
  JOIN runtime_run_command_receipts receipt ON receipt.id = NEW.source_receipt_id
  JOIN runtime_assignments assignment ON assignment.id = command.runtime_assignment_id
  WHERE command.id = NEW.source_command_id
    AND dispatch.status IN ('processing', 'awaiting-receipt', 'compensating')
    AND receipt.command_id = command.id
    AND (
      receipt.outcome = 'enforced' OR
      (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced')
    )
    AND NOT EXISTS (
      SELECT 1 FROM runtime_run_command_effects effect
      WHERE effect.command_id = command.id
    )
    AND command.session_id = NEW.session_id
    AND assignment.team_id = NEW.team_id
    AND assignment.project_id = NEW.project_id
    AND command.agent_run_id = NEW.agent_run_id
    AND command.run_policy_revision = NEW.run_policy_revision
    AND command.runtime_assignment_id = NEW.runtime_assignment_id
    AND command.runtime_assignment_generation = NEW.runtime_assignment_generation
    AND command.sandbox_id = NEW.sandbox_id
    AND command.sandbox_generation = NEW.sandbox_generation
    AND command.runtime_principal_id = NEW.runtime_principal_id
    AND command.runtime_authorization_generation = NEW.runtime_authorization_generation
    AND command.command_digest = NEW.source_command_digest
    AND command.authority_digest = NEW.lifecycle_command_claims_digest
    AND receipt.receipt_digest = NEW.lifecycle_receipt_digest
    AND json_extract(
      receipt.receipt_json,
      CASE WHEN receipt.outcome = 'duplicate'
        THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
    ) = NEW.source_enforced_fence
    AND command.required_effect_enforcer_set_digest =
      NEW.source_required_effect_enforcer_set_digest
    AND receipt.required_effect_enforcer_set_digest =
      NEW.source_required_effect_enforcer_set_digest
    AND receipt.enforcement_subject_digest = NEW.lifecycle_enforcement_subject_digest
    AND receipt.aggregate_proof_digest = NEW.lifecycle_aggregate_proof_digest
    AND receipt.proof_verified_at_ms = NEW.source_proof_verified_at_ms
    AND NEW.source_proof_verified_at_ms <= receipt.received_at_ms
    AND json_extract(
      receipt.receipt_json,
      CASE WHEN receipt.outcome = 'duplicate'
        THEN '$.originalReceipt.effectRef' ELSE '$.effectRef' END
    ) = NEW.source_effect_ref_commitment
    AND NEW.created_at_ms = receipt.received_at_ms
    AND EXISTS (
      SELECT 1 FROM runtime_binding_safety_fences safety
      WHERE safety.team_id = NEW.team_id
        AND safety.project_id = NEW.project_id
        AND safety.session_id = NEW.session_id
        AND safety.runtime_assignment_id = NEW.runtime_assignment_id
        AND safety.runtime_assignment_generation = NEW.runtime_assignment_generation
        AND safety.sandbox_id = NEW.sandbox_id
        AND safety.sandbox_generation = NEW.sandbox_generation
        AND safety.runtime_principal_id = NEW.runtime_principal_id
        AND safety.allocated_fence = NEW.safety_fence
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation incident lacks exact verified source evidence');
END;

CREATE TRIGGER runtime_compensation_incidents_immutable_update
BEFORE UPDATE ON runtime_compensation_incidents
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation incidents are immutable');
END;

CREATE TRIGGER runtime_compensation_incidents_immutable_delete
BEFORE DELETE ON runtime_compensation_incidents
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation incidents are immutable');
END;

CREATE TRIGGER runtime_compensation_commands_valid_insert
BEFORE INSERT ON runtime_compensation_commands
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_compensation_incidents incident
  JOIN runtime_run_command_dispatch source_dispatch
    ON source_dispatch.command_id = incident.source_command_id
  WHERE incident.compensation_id = NEW.compensation_id
    AND incident.source_command_id = NEW.source_command_id
    AND incident.trust_state = 'verified'
    AND source_dispatch.status = 'compensating'
    AND NOT EXISTS (
      SELECT 1 FROM runtime_compensation_effects effect
      WHERE effect.compensation_id = NEW.compensation_id
    )
    AND incident.session_id = NEW.session_id
    AND incident.team_id = NEW.team_id
    AND incident.project_id = NEW.project_id
    AND incident.agent_run_id = NEW.agent_run_id
    AND incident.runtime_assignment_id = NEW.runtime_assignment_id
    AND incident.runtime_assignment_generation = NEW.runtime_assignment_generation
    AND incident.sandbox_id = NEW.sandbox_id
    AND incident.sandbox_generation = NEW.sandbox_generation
    AND incident.runtime_principal_id = NEW.runtime_principal_id
    AND incident.runtime_authorization_generation =
      NEW.observed_runtime_authorization_generation
    AND incident.source_required_effect_enforcer_set_digest =
      NEW.source_required_effect_enforcer_set_digest
    AND incident.lifecycle_command_claims_digest = NEW.lifecycle_command_claims_digest
    AND incident.lifecycle_receipt_digest = NEW.lifecycle_receipt_digest
    AND incident.lifecycle_enforcement_subject_digest =
      NEW.lifecycle_enforcement_subject_digest
    AND incident.lifecycle_aggregate_proof_digest = NEW.lifecycle_aggregate_proof_digest
    AND incident.safety_fence = NEW.safety_fence
    AND NEW.reason_ref = incident.incident_digest
    AND COALESCE(json_extract(NEW.command_json, '$.kind') = 'safety.quarantine', 0)
    AND COALESCE(json_extract(NEW.command_json, '$.commandId') = NEW.id, 0)
    AND COALESCE(
      json_extract(NEW.command_json, '$.compensationId') = NEW.compensation_id,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.observedRuntimeAuthorizationGeneration') =
        NEW.observed_runtime_authorization_generation,
      0
    )
    AND COALESCE(json_extract(NEW.command_json, '$.binding.teamId') = NEW.team_id, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.binding.projectId') = NEW.project_id, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.binding.sessionId') = NEW.session_id, 0)
    AND COALESCE(
      json_extract(NEW.command_json, '$.binding.runtimeAssignmentId') =
        NEW.runtime_assignment_id,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.binding.runtimeAssignmentGeneration') =
        NEW.runtime_assignment_generation,
      0
    )
    AND COALESCE(json_extract(NEW.command_json, '$.binding.sandboxId') = NEW.sandbox_id, 0)
    AND COALESCE(
      json_extract(NEW.command_json, '$.binding.sandboxGeneration') = NEW.sandbox_generation,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.binding.runtimePrincipalId') =
        NEW.runtime_principal_id,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.source.lifecycleCommandId') = NEW.source_command_id,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.source.lifecycleCommandClaimsDigest') =
        NEW.lifecycle_command_claims_digest,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.source.lifecycleReceiptDigest') =
        NEW.lifecycle_receipt_digest,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.source.lifecycleEnforcementSubjectDigest') =
        NEW.lifecycle_enforcement_subject_digest,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.source.lifecycleAggregateProofDigest') =
        NEW.lifecycle_aggregate_proof_digest,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.source.sourceRequiredEffectEnforcerSetDigest') =
        NEW.source_required_effect_enforcer_set_digest,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.platformSecurityPolicyRevision') =
        NEW.platform_security_policy_revision,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.requiredContainmentEnforcerSetDigest') =
        NEW.required_containment_enforcer_set_digest,
      0
    )
    AND COALESCE(json_extract(NEW.command_json, '$.safetyFence') = NEW.safety_fence, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.containment.revokeTerminalWrites') = 1, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.containment.stopProcessExecution') = 1, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.containment.quarantineRuntime') = 1, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.exactBindingOnly') = 1, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.advanceBeyondCurrentFences') = 1, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.reasonRef') = NEW.reason_ref, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.causationId') = NEW.causation_id, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.actor.kind') = 'system', 0)
    AND COALESCE(
      json_extract(NEW.command_json, '$.actor.actorRef') = 'platform-security',
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.authority.issuer') = 'platform-security',
      0
    )
    AND COALESCE(json_extract(NEW.command_json, '$.authority.audience') = 'runtime', 0)
    AND COALESCE(
      json_extract(NEW.command_json, '$.authority.capability') = 'safety.quarantine',
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.authority.claimsDigest') = NEW.authority_digest,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.authority.issuedAtMs') <=
        NEW.authority_verified_at_ms,
      0
    )
    AND COALESCE(
      json_extract(NEW.command_json, '$.authority.expiresAtMs') >
        NEW.authority_verified_at_ms,
      0
    )
    AND COALESCE(json_extract(NEW.command_json, '$.issuedAtMs') = NEW.created_at_ms, 0)
    AND COALESCE(json_extract(NEW.command_json, '$.deadlineAtMs') = NEW.deadline_at_ms, 0)
    AND (
      (NEW.command_sequence = 1 AND NOT EXISTS (
        SELECT 1 FROM runtime_compensation_commands previous
        WHERE previous.compensation_id = NEW.compensation_id
      )) OR
      (NEW.command_sequence > 1 AND EXISTS (
        SELECT 1
        FROM runtime_compensation_commands previous
        JOIN runtime_compensation_dispatch previous_dispatch
          ON previous_dispatch.compensation_command_id = previous.id
        WHERE previous.compensation_id = NEW.compensation_id
          AND previous.command_sequence = NEW.previous_command_sequence
          AND previous_dispatch.status = 'expired-before-dispatch'
      ))
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation command is not exact platform-security work');
END;

CREATE TRIGGER runtime_compensation_commands_immutable_update
BEFORE UPDATE ON runtime_compensation_commands
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation commands are immutable');
END;

CREATE TRIGGER runtime_compensation_commands_immutable_delete
BEFORE DELETE ON runtime_compensation_commands
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation commands are immutable');
END;

CREATE TRIGGER runtime_compensation_dispatch_initial_state
BEFORE INSERT ON runtime_compensation_dispatch
WHEN NEW.status <> 'pending' OR NEW.attempts <> 0 OR
  NEW.available_at_ms <> NEW.created_at_ms OR NEW.lease_owner IS NOT NULL OR
  NEW.lease_expires_at_ms IS NOT NULL OR
  NEW.dispatch_interlock_acquired_at_ms IS NOT NULL OR
  NEW.last_safe_error_code IS NOT NULL OR NEW.terminal_at_ms IS NOT NULL OR
  NEW.updated_at_ms <> NEW.created_at_ms
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation dispatch must begin pending');
END;

CREATE TRIGGER runtime_compensation_dispatch_identity_immutable
BEFORE UPDATE OF compensation_command_id, compensation_id, source_command_id, created_at_ms
ON runtime_compensation_dispatch
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation dispatch identity is immutable');
END;

CREATE TRIGGER runtime_compensation_dispatch_immutable_delete
BEFORE DELETE ON runtime_compensation_dispatch
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation dispatch cannot be deleted');
END;

CREATE TRIGGER runtime_compensation_dispatch_valid_transition
BEFORE UPDATE ON runtime_compensation_dispatch
WHEN
  OLD.status IN ('enforced', 'blocked', 'expired-before-dispatch') OR
  NEW.updated_at_ms < OLD.updated_at_ms OR
  NOT COALESCE((
    (OLD.status = 'pending' AND NEW.status = 'processing'
      AND NEW.attempts = OLD.attempts + 1
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.updated_at_ms >= OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS NULL) OR
    (OLD.status = 'pending' AND NEW.status = 'expired-before-dispatch'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.last_safe_error_code = 'deadline_expired') OR
    (OLD.status = 'processing' AND NEW.status = 'processing'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.lease_owner = OLD.lease_owner
      AND NEW.updated_at_ms < OLD.lease_expires_at_ms
      AND NEW.lease_expires_at_ms >= OLD.lease_expires_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.dispatch_interlock_acquired_at_ms = NEW.updated_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms < NEW.lease_expires_at_ms) OR
    (OLD.status = 'processing' AND NEW.status = 'pending'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.last_safe_error_code IN (
        'invalid_input', 'invalid_authority', 'authority_verification_failed',
        'binding_mismatch', 'runtime_handle_unavailable', 'lease_expired_before_dispatch'
      )
      AND NOT EXISTS (
        SELECT 1 FROM runtime_compensation_receipts receipt
        WHERE receipt.compensation_command_id = OLD.compensation_command_id
      )) OR
    (OLD.status = 'processing' AND NEW.status = 'expired-before-dispatch'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.last_safe_error_code IN ('deadline_expired', 'lease_expired_before_dispatch')
      AND NOT EXISTS (
        SELECT 1 FROM runtime_compensation_receipts receipt
        WHERE receipt.compensation_command_id = OLD.compensation_command_id
      )) OR
    (OLD.status = 'processing' AND NEW.status = 'awaiting-receipt'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NOT NULL
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms) OR
    (OLD.status = 'processing' AND NEW.status IN ('enforced', 'blocked')
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NOT NULL
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status = 'awaiting-receipt'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status IN ('enforced', 'blocked')
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms)
  ), 0)
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime compensation dispatch transition');
END;

CREATE TRIGGER runtime_compensation_receipts_dispatch_state
BEFORE INSERT ON runtime_compensation_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_compensation_dispatch dispatch
  WHERE dispatch.compensation_command_id = NEW.compensation_command_id
    AND dispatch.compensation_id = NEW.compensation_id
    AND dispatch.source_command_id = NEW.source_command_id
    AND (
      (dispatch.status = 'processing'
        AND dispatch.dispatch_interlock_acquired_at_ms IS NOT NULL) OR
      dispatch.status = 'awaiting-receipt'
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation dispatch is not accepting receipts');
END;

CREATE TRIGGER runtime_compensation_receipts_exact_command
BEFORE INSERT ON runtime_compensation_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_compensation_commands command
  WHERE command.id = NEW.compensation_command_id
    AND command.compensation_id = NEW.compensation_id
    AND command.source_command_id = NEW.source_command_id
    AND command.session_id = NEW.session_id
    AND command.team_id = NEW.team_id
    AND command.project_id = NEW.project_id
    AND command.agent_run_id = NEW.agent_run_id
    AND command.runtime_assignment_id = NEW.runtime_assignment_id
    AND command.runtime_assignment_generation = NEW.runtime_assignment_generation
    AND command.sandbox_id = NEW.sandbox_id
    AND command.sandbox_generation = NEW.sandbox_generation
    AND command.runtime_principal_id = NEW.runtime_principal_id
    AND command.observed_runtime_authorization_generation =
      NEW.observed_runtime_authorization_generation
    AND command.command_digest = NEW.command_digest
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation receipt does not match its command');
END;

CREATE TRIGGER runtime_compensation_receipts_enforcement_proof
BEFORE INSERT ON runtime_compensation_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_compensation_commands command
  WHERE command.id = NEW.compensation_command_id
    AND (
      ((NEW.outcome = 'enforced' OR
        (NEW.outcome = 'duplicate' AND NEW.original_outcome = 'enforced'))
        AND NEW.required_containment_enforcer_set_digest =
          command.required_containment_enforcer_set_digest
        AND NEW.effect_ref_commitment IS NOT NULL
        AND length(NEW.effect_ref_commitment) = 74
        AND substr(NEW.effect_ref_commitment, 1, 10) = 'effect:v1:'
        AND substr(NEW.effect_ref_commitment, 11) NOT GLOB '*[^0-9a-f]*'
        AND NEW.enforcement_subject_digest IS NOT NULL
        AND NEW.aggregate_proof_digest IS NOT NULL
        AND NEW.proof_verified_at_ms IS NOT NULL
        AND NEW.proof_verified_at_ms <= NEW.received_at_ms
        AND NEW.enforced_safety_fence >= command.safety_fence
        AND COALESCE(json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.enforcedSafetyFence'
            ELSE '$.enforcedSafetyFence' END
        ) = NEW.enforced_safety_fence, 0)
        AND COALESCE(json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.effectRef' ELSE '$.effectRef' END
        ) = NEW.effect_ref_commitment, 0)
        AND COALESCE(json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.containment.terminalWritesRevoked'
            ELSE '$.containment.terminalWritesRevoked' END
        ) = 1, 0)
        AND COALESCE(json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.containment.processExecutionStopped'
            ELSE '$.containment.processExecutionStopped' END
        ) = 1, 0)
        AND COALESCE(json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.containment.runtimeQuarantined'
            ELSE '$.containment.runtimeQuarantined' END
        ) = 1, 0)
        AND COALESCE(json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.aggregateEnforcementProof.generation'
            ELSE '$.aggregateEnforcementProof.generation' END
        ) = command.observed_runtime_authorization_generation, 0)
        AND COALESCE(json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.aggregateEnforcementProof.requiredEffectEnforcerSetDigest'
            ELSE '$.aggregateEnforcementProof.requiredEffectEnforcerSetDigest' END
        ) = NEW.required_containment_enforcer_set_digest, 0)
        AND COALESCE(json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.aggregateEnforcementProof.enforcementSubjectDigest'
            ELSE '$.aggregateEnforcementProof.enforcementSubjectDigest' END
        ) = NEW.enforcement_subject_digest, 0)
        AND COALESCE(json_extract(
          NEW.receipt_json,
          CASE WHEN NEW.outcome = 'duplicate'
            THEN '$.originalReceipt.aggregateEnforcementProof.aggregateProofDigest'
            ELSE '$.aggregateEnforcementProof.aggregateProofDigest' END
        ) = NEW.aggregate_proof_digest, 0)) OR
      (NOT (NEW.outcome = 'enforced' OR
        (NEW.outcome = 'duplicate' AND NEW.original_outcome = 'enforced'))
        AND NEW.required_containment_enforcer_set_digest IS NULL
        AND NEW.enforcement_subject_digest IS NULL
        AND NEW.aggregate_proof_digest IS NULL
        AND NEW.proof_verified_at_ms IS NULL
        AND NEW.enforced_safety_fence IS NULL
        AND (
          ((NEW.outcome IN ('accepted', 'quarantined') OR
            (NEW.outcome = 'duplicate' AND NEW.original_outcome IN (
              'accepted', 'quarantined'
            )))
            AND NEW.effect_ref_commitment IS NOT NULL
            AND COALESCE(json_extract(
              NEW.receipt_json,
              CASE WHEN NEW.outcome = 'duplicate'
                THEN '$.originalReceipt.effectRef' ELSE '$.effectRef' END
            ) = NEW.effect_ref_commitment, 0)) OR
          ((NEW.outcome = 'rejected' OR
            (NEW.outcome = 'duplicate' AND NEW.original_outcome = 'rejected'))
            AND NEW.effect_ref_commitment IS NULL)
        ))
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation receipt lacks exact containment evidence');
END;

CREATE TRIGGER runtime_compensation_receipts_version_continuity
BEFORE INSERT ON runtime_compensation_receipts
WHEN NEW.previous_version IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM runtime_compensation_receipts previous
  WHERE previous.compensation_command_id = NEW.compensation_command_id
    AND previous.version = NEW.previous_version
    AND previous.received_at_ms <= NEW.received_at_ms
    AND (
      (previous.outcome = 'accepted' AND (
        NEW.outcome IN ('enforced', 'rejected', 'quarantined') OR
        (NEW.outcome = 'duplicate'
          AND NEW.original_outcome = 'accepted'
          AND NEW.original_receipt_digest = previous.receipt_digest)
      )) OR
      (previous.outcome IN ('enforced', 'rejected', 'quarantined')
        AND NEW.outcome = 'duplicate'
        AND NEW.original_outcome = previous.outcome
        AND NEW.original_receipt_digest = previous.receipt_digest) OR
      (previous.outcome = 'duplicate' AND previous.original_outcome = 'accepted' AND (
        NEW.outcome IN ('enforced', 'rejected', 'quarantined') OR
        (NEW.outcome = 'duplicate'
          AND NEW.original_outcome = 'accepted'
          AND NEW.original_receipt_digest = previous.original_receipt_digest)
      )) OR
      (previous.outcome = 'duplicate'
        AND previous.original_outcome IN ('enforced', 'rejected', 'quarantined')
        AND NEW.outcome = 'duplicate'
        AND NEW.original_outcome = previous.original_outcome
        AND NEW.original_receipt_digest = previous.original_receipt_digest)
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime compensation receipt version continuity');
END;

CREATE TRIGGER runtime_compensation_receipts_immutable_update
BEFORE UPDATE ON runtime_compensation_receipts
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation receipts are immutable');
END;

CREATE TRIGGER runtime_compensation_receipts_immutable_delete
BEFORE DELETE ON runtime_compensation_receipts
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation receipts are immutable');
END;

CREATE TRIGGER runtime_compensation_effects_verified_receipt
BEFORE INSERT ON runtime_compensation_effects
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_compensation_receipts receipt
  JOIN runtime_compensation_commands command
    ON command.id = receipt.compensation_command_id
  JOIN runtime_compensation_incidents incident
    ON incident.compensation_id = command.compensation_id
  JOIN runtime_run_command_dispatch source_dispatch
    ON source_dispatch.command_id = incident.source_command_id
  JOIN runtime_compensation_dispatch compensation_dispatch
    ON compensation_dispatch.compensation_command_id = command.id
  JOIN runtime_binding_safety_fences safety
    ON safety.team_id = command.team_id
   AND safety.project_id = command.project_id
   AND safety.session_id = command.session_id
   AND safety.runtime_assignment_id = command.runtime_assignment_id
   AND safety.runtime_assignment_generation = command.runtime_assignment_generation
   AND safety.sandbox_id = command.sandbox_id
   AND safety.sandbox_generation = command.sandbox_generation
   AND safety.runtime_principal_id = command.runtime_principal_id
  WHERE receipt.id = NEW.receipt_id
    AND receipt.compensation_command_id = NEW.compensation_command_id
    AND receipt.compensation_id = NEW.compensation_id
    AND receipt.source_command_id = NEW.source_command_id
    AND (
      receipt.outcome = 'enforced' OR
      (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced')
    )
    AND receipt.required_containment_enforcer_set_digest =
      command.required_containment_enforcer_set_digest
    AND receipt.effect_ref_commitment IS NOT NULL
    AND receipt.enforcement_subject_digest IS NOT NULL
    AND receipt.aggregate_proof_digest IS NOT NULL
    AND receipt.proof_verified_at_ms IS NOT NULL
    AND receipt.proof_verified_at_ms <= receipt.received_at_ms
    AND receipt.received_at_ms <= NEW.applied_at_ms
    AND safety.allocated_fence >= receipt.enforced_safety_fence
    AND incident.trust_state = 'verified'
    AND incident.session_id = NEW.session_id
    AND incident.agent_run_id = NEW.agent_run_id
    AND source_dispatch.status = 'compensating'
    AND (
      (compensation_dispatch.status = 'processing'
        AND compensation_dispatch.dispatch_interlock_acquired_at_ms IS NOT NULL) OR
      compensation_dispatch.status = 'awaiting-receipt'
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation effect requires exact verified containment');
END;

CREATE TRIGGER runtime_compensation_effects_event_binding
BEFORE INSERT ON runtime_compensation_effects
WHEN NOT EXISTS (
  SELECT 1 FROM session_events event
  WHERE event.session_id = NEW.session_id
    AND event.sequence = NEW.applied_session_sequence
    AND event.type = 'run.runtime-command.compensated'
    AND json_extract(event.payload_json, '$.compensationId') = NEW.compensation_id
    AND json_extract(event.payload_json, '$.sourceCommandId') = NEW.source_command_id
    AND json_extract(event.payload_json, '$.compensationCommandId') =
      NEW.compensation_command_id
    AND json_extract(event.payload_json, '$.receiptId') = NEW.receipt_id
    AND json_extract(event.payload_json, '$.effectDigest') = NEW.effect_digest
    AND json_extract(event.payload_json, '$.agentRunId') = NEW.agent_run_id
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation effect event does not match');
END;

CREATE TRIGGER runtime_compensation_effects_immutable_update
BEFORE UPDATE ON runtime_compensation_effects
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation effects are immutable');
END;

CREATE TRIGGER runtime_compensation_effects_immutable_delete
BEFORE DELETE ON runtime_compensation_effects
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation effects are immutable');
END;

CREATE TRIGGER runtime_compensation_referenced_events_immutable_update
BEFORE UPDATE ON session_events
WHEN EXISTS (
  SELECT 1 FROM runtime_compensation_effects effect
  WHERE effect.session_id = OLD.session_id
    AND effect.applied_session_sequence = OLD.sequence
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation journal events are immutable');
END;

CREATE TRIGGER runtime_compensation_referenced_events_immutable_delete
BEFORE DELETE ON session_events
WHEN EXISTS (
  SELECT 1 FROM runtime_compensation_effects effect
  WHERE effect.session_id = OLD.session_id
    AND effect.applied_session_sequence = OLD.sequence
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation journal events are immutable');
END;

CREATE TRIGGER runtime_compensation_dispatch_terminal_evidence
BEFORE UPDATE OF status ON runtime_compensation_dispatch
WHEN
  (NEW.status = 'enforced' AND NOT EXISTS (
    SELECT 1 FROM runtime_compensation_effects effect
    WHERE effect.compensation_command_id = NEW.compensation_command_id
      AND effect.compensation_id = NEW.compensation_id
      AND effect.source_command_id = NEW.source_command_id
  )) OR
  (NEW.status = 'blocked' AND NOT EXISTS (
    SELECT 1 FROM runtime_compensation_receipts receipt
    WHERE receipt.compensation_command_id = NEW.compensation_command_id
      AND (
        receipt.outcome IN ('rejected', 'quarantined') OR
        (receipt.outcome = 'duplicate'
          AND receipt.original_outcome IN ('rejected', 'quarantined'))
      )
  )) OR
  (NEW.status = 'expired-before-dispatch' AND (
    NEW.dispatch_interlock_acquired_at_ms IS NOT NULL OR
    EXISTS (
      SELECT 1 FROM runtime_compensation_receipts receipt
      WHERE receipt.compensation_command_id = NEW.compensation_command_id
    ) OR EXISTS (
      SELECT 1 FROM runtime_compensation_effects effect
      WHERE effect.compensation_command_id = NEW.compensation_command_id
    )
  ))
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation terminal state lacks durable evidence');
END;
`;

const RUNTIME_COMPENSATION_INTEGRATION_TRIGGERS_SCHEMA_V7 = `
CREATE TRIGGER runtime_run_command_receipts_safe_enforced_fence_v7
BEFORE INSERT ON runtime_run_command_receipts
WHEN (NEW.outcome = 'enforced' OR
    (NEW.outcome = 'duplicate' AND NEW.original_outcome = 'enforced'))
  AND (
    COALESCE(json_type(
      NEW.receipt_json,
      CASE WHEN NEW.outcome = 'duplicate'
        THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
    ) = 'integer', 0) = 0 OR
    json_extract(
      NEW.receipt_json,
      CASE WHEN NEW.outcome = 'duplicate'
        THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
    ) < 1 OR
    json_extract(
      NEW.receipt_json,
      CASE WHEN NEW.outcome = 'duplicate'
        THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
    ) > 9007199254740991
  )
BEGIN
  SELECT RAISE(ABORT, 'Runtime enforced receipt fence is not a safe integer');
END;

CREATE TRIGGER runtime_compensation_follow_events_valid_insert
BEFORE INSERT ON runtime_compensation_follow_events
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_receipt_follow_streams stream
  JOIN runtime_compensation_commands command
    ON command.id = NEW.compensation_command_id
  JOIN runtime_compensation_receipts receipt ON receipt.id = NEW.receipt_id
  WHERE stream.runtime_assignment_id = NEW.runtime_assignment_id
    AND stream.runtime_authorization_generation = NEW.runtime_authorization_generation
    AND stream.status = 'processing'
    AND stream.lease_owner = NEW.lease_owner
    AND stream.lease_version = NEW.lease_version
    AND stream.lease_expires_at_ms > NEW.received_at_ms
    AND NEW.receipt_sequence = stream.receipt_sequence + 1
    AND NEW.previous_cursor IS stream.cursor
    AND NEW.previous_observation_digest IS stream.last_observation_digest
    AND command.compensation_id = NEW.compensation_id
    AND command.source_command_id = NEW.source_command_id
    AND command.session_id = NEW.session_id
    AND command.runtime_assignment_id = NEW.runtime_assignment_id
    AND command.runtime_assignment_generation = NEW.runtime_assignment_generation
    AND command.sandbox_id = NEW.sandbox_id
    AND command.sandbox_generation = NEW.sandbox_generation
    AND command.runtime_principal_id = NEW.runtime_principal_id
    AND command.observed_runtime_authorization_generation =
      NEW.runtime_authorization_generation
    AND command.command_digest = NEW.command_digest
    AND receipt.compensation_command_id = command.id
    AND receipt.compensation_id = command.compensation_id
    AND receipt.observed_runtime_authorization_generation =
      NEW.runtime_authorization_generation
    AND receipt.receipt_digest = NEW.effective_receipt_digest
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation follow event is not exact-bound');
END;

CREATE TRIGGER runtime_compensation_follow_events_cross_lifecycle
BEFORE INSERT ON runtime_compensation_follow_events
WHEN EXISTS (
  SELECT 1 FROM runtime_receipt_follow_events event
  WHERE event.id = NEW.id OR
    (event.runtime_assignment_id = NEW.runtime_assignment_id
      AND event.runtime_authorization_generation = NEW.runtime_authorization_generation
      AND (event.receipt_sequence = NEW.receipt_sequence OR
        event.cursor = NEW.cursor OR event.observation_digest = NEW.observation_digest))
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime follow observation conflicts across ledgers');
END;

CREATE TRIGGER runtime_receipt_follow_events_cross_compensation
BEFORE INSERT ON runtime_receipt_follow_events
WHEN EXISTS (
  SELECT 1 FROM runtime_compensation_follow_events event
  WHERE event.id = NEW.id OR
    (event.runtime_assignment_id = NEW.runtime_assignment_id
      AND event.runtime_authorization_generation = NEW.runtime_authorization_generation
      AND (event.receipt_sequence = NEW.receipt_sequence OR
        event.cursor = NEW.cursor OR event.observation_digest = NEW.observation_digest))
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime follow observation conflicts across ledgers');
END;

CREATE TRIGGER runtime_compensation_follow_events_immutable_update
BEFORE UPDATE ON runtime_compensation_follow_events
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation follow events are immutable');
END;

CREATE TRIGGER runtime_compensation_follow_events_immutable_delete
BEFORE DELETE ON runtime_compensation_follow_events
BEGIN
  SELECT RAISE(ABORT, 'Runtime compensation follow events cannot be deleted');
END;

DROP TRIGGER runtime_receipt_follow_streams_valid_transition;

CREATE TRIGGER runtime_receipt_follow_streams_valid_transition
BEFORE UPDATE ON runtime_receipt_follow_streams
WHEN NEW.updated_at_ms < OLD.updated_at_ms OR NOT (
  (OLD.status = 'pending' AND NEW.status = 'processing'
    AND NEW.attempts = OLD.attempts + 1
    AND NEW.lease_version = OLD.lease_version + 1
    AND NEW.available_at_ms = OLD.available_at_ms
    AND NEW.cursor IS OLD.cursor
    AND NEW.last_observation_digest IS OLD.last_observation_digest
    AND NEW.receipt_sequence = OLD.receipt_sequence
    AND NEW.updated_at_ms >= OLD.available_at_ms) OR
  (OLD.status = 'pending' AND NEW.status = 'pending'
    AND NEW.attempts = OLD.attempts
    AND NEW.lease_version = OLD.lease_version
    AND NEW.available_at_ms >= OLD.available_at_ms
    AND NEW.available_at_ms >= NEW.updated_at_ms
    AND NEW.cursor IS OLD.cursor
    AND NEW.last_observation_digest IS OLD.last_observation_digest
    AND NEW.receipt_sequence = OLD.receipt_sequence) OR
  (OLD.status = 'processing' AND NEW.status = 'processing'
    AND NEW.attempts = OLD.attempts
    AND NEW.lease_version = OLD.lease_version
    AND NEW.available_at_ms = OLD.available_at_ms
    AND NEW.lease_owner = OLD.lease_owner
    AND NEW.cursor IS OLD.cursor
    AND NEW.last_observation_digest IS OLD.last_observation_digest
    AND NEW.receipt_sequence = OLD.receipt_sequence
    AND NEW.updated_at_ms < OLD.lease_expires_at_ms
    AND NEW.lease_expires_at_ms >= OLD.lease_expires_at_ms) OR
  (OLD.status = 'processing' AND NEW.status = 'pending'
    AND NEW.attempts = OLD.attempts
    AND NEW.lease_version = OLD.lease_version
    AND NEW.available_at_ms >= OLD.available_at_ms
    AND NEW.available_at_ms >= NEW.updated_at_ms
    AND (
      (NEW.cursor IS OLD.cursor
        AND NEW.last_observation_digest IS OLD.last_observation_digest
        AND NEW.receipt_sequence = OLD.receipt_sequence) OR
      (NEW.cursor IS NOT NULL
        AND NEW.last_observation_digest IS NOT NULL
        AND NEW.receipt_sequence = OLD.receipt_sequence + 1
        AND 1 = (
          SELECT COUNT(*) FROM (
            SELECT event.id FROM runtime_receipt_follow_events event
            WHERE event.runtime_assignment_id = OLD.runtime_assignment_id
              AND event.runtime_authorization_generation = OLD.runtime_authorization_generation
              AND event.receipt_sequence = NEW.receipt_sequence
              AND event.cursor = NEW.cursor
              AND event.observation_digest = NEW.last_observation_digest
              AND event.lease_owner = OLD.lease_owner
              AND event.lease_version = OLD.lease_version
            UNION ALL
            SELECT event.id FROM runtime_compensation_follow_events event
            WHERE event.runtime_assignment_id = OLD.runtime_assignment_id
              AND event.runtime_authorization_generation = OLD.runtime_authorization_generation
              AND event.receipt_sequence = NEW.receipt_sequence
              AND event.cursor = NEW.cursor
              AND event.observation_digest = NEW.last_observation_digest
              AND event.lease_owner = OLD.lease_owner
              AND event.lease_version = OLD.lease_version
          )
        ))
    )) OR
  (OLD.status IN ('pending', 'processing') AND NEW.status = 'quarantined'
    AND NEW.attempts = OLD.attempts
    AND NEW.lease_version = OLD.lease_version
    AND NEW.available_at_ms = OLD.available_at_ms
    AND NEW.cursor IS OLD.cursor
    AND NEW.last_observation_digest IS OLD.last_observation_digest
    AND NEW.receipt_sequence = OLD.receipt_sequence
    AND NEW.last_safe_error_code IS NOT NULL) OR
  (OLD.status = 'quarantined' AND NEW.status = 'quarantined'
    AND NEW.attempts = OLD.attempts
    AND NEW.lease_version = OLD.lease_version
    AND NEW.available_at_ms = OLD.available_at_ms
    AND NEW.cursor IS OLD.cursor
    AND NEW.last_observation_digest IS OLD.last_observation_digest
    AND NEW.receipt_sequence = OLD.receipt_sequence
    AND NEW.last_safe_error_code = OLD.last_safe_error_code)
)
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime receipt follow stream transition');
END;

DROP TRIGGER runtime_run_command_dispatch_valid_transition;

CREATE TRIGGER runtime_run_command_dispatch_valid_transition
BEFORE UPDATE ON runtime_run_command_dispatch
WHEN
  OLD.status IN ('enforced', 'rejected', 'quarantined', 'superseded', 'failed') OR
  NEW.updated_at_ms < OLD.updated_at_ms OR
  NOT (
    (OLD.status = 'pending' AND NEW.status = 'processing'
      AND NEW.attempts = OLD.attempts + 1
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.updated_at_ms >= OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS NULL
      AND (
        OLD.attempts = 0 OR COALESCE(OLD.last_safe_error_code IN (
            'invalid_input', 'invalid_authority', 'authority_verification_failed',
            'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
            'lease_expired_before_dispatch'
          ), 0)
      )) OR
    (OLD.status = 'pending' AND NEW.status = 'pending'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND (
        OLD.attempts = 0 OR COALESCE(
          NEW.last_safe_error_code = OLD.last_safe_error_code,
          0
        )
      )) OR
    (OLD.status = 'pending' AND NEW.status = 'failed'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND COALESCE(NEW.last_safe_error_code IN (
          'invalid_input', 'invalid_authority', 'authority_verification_failed',
          'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
          'lease_expired_before_dispatch'
        ), 0)
      AND (
        OLD.attempts = 0 OR COALESCE(
          NEW.last_safe_error_code = OLD.last_safe_error_code,
          0
        )
      )) OR
    (OLD.status = 'pending' AND NEW.status = 'superseded'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND NEW.last_safe_error_code = 'state_fence_superseded'
      AND (
        OLD.attempts = 0 OR COALESCE(OLD.last_safe_error_code IN (
            'invalid_input', 'invalid_authority', 'authority_verification_failed',
            'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
            'lease_expired_before_dispatch'
          ), 0)
      )) OR
    (OLD.status = 'processing' AND NEW.status = 'processing'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.lease_owner = OLD.lease_owner
      AND NEW.updated_at_ms < OLD.lease_expires_at_ms
      AND NEW.lease_expires_at_ms >= OLD.lease_expires_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.dispatch_interlock_acquired_at_ms = NEW.updated_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms < NEW.lease_expires_at_ms) OR
    (OLD.status = 'processing' AND NEW.status = 'pending'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND COALESCE(NEW.last_safe_error_code IN (
          'invalid_input', 'invalid_authority', 'authority_verification_failed',
          'binding_mismatch', 'deadline_expired', 'runtime_handle_unavailable',
          'lease_expired_before_dispatch'
        ), 0)
      AND (
        NEW.updated_at_ms < OLD.lease_expires_at_ms OR (
          OLD.dispatch_interlock_acquired_at_ms IS NULL
          AND NEW.last_safe_error_code IN (
            'lease_expired_before_dispatch', 'deadline_expired'
          )
          AND NEW.updated_at_ms >= OLD.lease_expires_at_ms
        )
      )
      AND NOT EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
      )) OR
    (OLD.status = 'processing' AND NEW.status = 'superseded'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.dispatch_interlock_acquired_at_ms IS NULL
      AND NEW.updated_at_ms < OLD.lease_expires_at_ms
      AND NEW.last_safe_error_code = 'state_fence_superseded'
      AND NOT EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
      )) OR
    (OLD.status = 'processing' AND NEW.status = 'awaiting-receipt'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND OLD.dispatch_interlock_acquired_at_ms IS NOT NULL
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms) OR
    (OLD.status = 'processing' AND NEW.status = 'compensating'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
          AND (
            receipt.outcome = 'enforced' OR
            (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced')
          )
      )
      AND EXISTS (
        SELECT 1 FROM runtime_compensation_incidents incident
        WHERE incident.source_command_id = OLD.command_id
          AND incident.trust_state = 'verified'
      )) OR
    (OLD.status = 'processing' AND NEW.status IN (
        'enforced', 'rejected', 'quarantined'
      )
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status = 'awaiting-receipt'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms >= OLD.available_at_ms
      AND NEW.available_at_ms >= NEW.updated_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status = 'compensating'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND EXISTS (
        SELECT 1 FROM runtime_run_command_receipts receipt
        WHERE receipt.command_id = OLD.command_id
          AND (
            receipt.outcome = 'enforced' OR
            (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced')
          )
      )
      AND EXISTS (
        SELECT 1 FROM runtime_compensation_incidents incident
        WHERE incident.source_command_id = OLD.command_id
          AND incident.trust_state = 'verified'
      )) OR
    (OLD.status = 'awaiting-receipt' AND NEW.status IN (
        'enforced', 'rejected', 'quarantined'
      )
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms) OR
    (OLD.status = 'compensating' AND NEW.status = 'quarantined'
      AND NEW.attempts = OLD.attempts
      AND NEW.available_at_ms = OLD.available_at_ms
      AND NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
      AND NEW.last_safe_error_code = 'stale_enforced_effect_compensated'
      AND EXISTS (
        SELECT 1 FROM runtime_compensation_effects effect
        JOIN runtime_compensation_dispatch compensation_dispatch
          ON compensation_dispatch.compensation_command_id = effect.compensation_command_id
        WHERE effect.source_command_id = OLD.command_id
          AND compensation_dispatch.compensation_id = effect.compensation_id
          AND compensation_dispatch.status = 'enforced'
      ))
  )
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime Run command dispatch transition');
END;

DROP TRIGGER runtime_run_command_dispatch_terminal_evidence;

CREATE TRIGGER runtime_run_command_dispatch_terminal_evidence
BEFORE UPDATE OF status ON runtime_run_command_dispatch
WHEN
  (NEW.status = 'enforced' AND (
    NOT EXISTS (
      SELECT 1 FROM runtime_run_command_effects effect
      WHERE effect.command_id = NEW.command_id
    ) OR
    NOT EXISTS (
      SELECT 1
      FROM runtime_run_commands command
      JOIN agent_runs run
        ON run.id = command.agent_run_id
       AND run.session_id = command.session_id
      JOIN goal_sets goal_set
        ON goal_set.agent_run_id = run.id
       AND goal_set.revision = run.current_goal_set_revision
      JOIN sessions session ON session.id = run.session_id
      JOIN runtime_assignments assignment
        ON assignment.id = run.runtime_assignment_id
       AND assignment.session_id = run.session_id
      WHERE command.id = NEW.command_id
        AND run.lifecycle = command.target_lifecycle
        AND run.state_version = command.target_run_state_version
        AND run.current_policy_revision = command.run_policy_revision
        AND run.current_goal_set_revision = command.goal_set_revision
        AND goal_set.goal_set_id = command.goal_set_id
        AND run.runtime_assignment_id = command.runtime_assignment_id
        AND run.runtime_authorization_generation = command.runtime_authorization_generation
        AND session.runtime_authorization_generation = command.runtime_authorization_generation
        AND session.runtime_authorization_state = 'enforced'
        AND assignment.generation = command.runtime_assignment_generation
        AND assignment.sandbox_id = command.sandbox_id
        AND assignment.sandbox_generation = command.sandbox_generation
        AND assignment.runtime_principal_id = command.runtime_principal_id
        AND assignment.runtime_authorization_generation = command.runtime_authorization_generation
        AND assignment.status = 'ready'
    )
  )) OR
  (NEW.status IN ('rejected', 'quarantined')
    AND NOT (
      NEW.status = 'quarantined'
      AND OLD.status = 'compensating'
      AND NEW.last_safe_error_code = 'stale_enforced_effect_compensated'
      AND EXISTS (
        SELECT 1 FROM runtime_compensation_effects effect
        JOIN runtime_compensation_dispatch compensation_dispatch
          ON compensation_dispatch.compensation_command_id = effect.compensation_command_id
        WHERE effect.source_command_id = NEW.command_id
          AND compensation_dispatch.compensation_id = effect.compensation_id
          AND compensation_dispatch.status = 'enforced'
      )
    )
    AND NOT EXISTS (
      SELECT 1 FROM runtime_run_command_receipts receipt
      WHERE receipt.command_id = NEW.command_id
        AND (
          receipt.outcome = NEW.status OR
          (receipt.outcome = 'duplicate' AND receipt.original_outcome = NEW.status)
        )
    ))
BEGIN
  SELECT RAISE(ABORT, 'Runtime Run dispatch terminal state lacks durable evidence');
END;
`;

const RUNTIME_OUTBOX_IDENTIFIER_TRIM_CODE_POINTS_SQL = [
  0x20, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
  0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff,
].join(", ");

function runtimeOutboxBoundedTextSql(valueSql: string): string {
  const controlCharacters = [...Array(32).keys(), 127]
    .map((codePoint) => `instr(${valueSql}, char(${codePoint})) > 0`)
    .join(" OR ");
  return `(
    typeof(${valueSql}) = 'text' AND
    length(${valueSql}) >= 1 AND
    length(CAST(${valueSql} AS BLOB)) <= 300 AND
    ${valueSql} = trim(${valueSql}) AND
    unicode(substr(${valueSql}, 1, 1))
      NOT IN (${RUNTIME_OUTBOX_IDENTIFIER_TRIM_CODE_POINTS_SQL}) AND
    unicode(substr(${valueSql}, -1, 1))
      NOT IN (${RUNTIME_OUTBOX_IDENTIFIER_TRIM_CODE_POINTS_SQL}) AND
    NOT (${controlCharacters})
  )`;
}

function hostedRuntimeBindingJsonSql(payloadSql: string, bindingPath = "$.binding"): string {
  const binding = `${payloadSql}, '${bindingPath}'`;
  const textFields = [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "sandboxId",
    "runtimePrincipalId",
  ];
  const texts = textFields
    .map((field) =>
      runtimeOutboxBoundedTextSql(`json_extract(${payloadSql}, '${bindingPath}.${field}')`)
    )
    .join(" AND ");
  return `(
    json_type(${payloadSql}, '${bindingPath}') = 'object' AND
    (SELECT count(*) = 8 AND count(*) = count(DISTINCT key) FROM json_each(${binding})) AND
    NOT EXISTS (
      SELECT 1 FROM json_each(${binding}) WHERE key NOT IN (
        'teamId', 'projectId', 'sessionId', 'runtimeAssignmentId',
        'runtimeAssignmentGeneration', 'sandboxId', 'sandboxGeneration', 'runtimePrincipalId'
      )
    ) AND
    ${texts} AND
    json_type(${payloadSql}, '${bindingPath}.runtimeAssignmentGeneration') = 'integer' AND
    json_extract(${payloadSql}, '${bindingPath}.runtimeAssignmentGeneration')
      BETWEEN 1 AND 9007199254740991 AND
    json_type(${payloadSql}, '${bindingPath}.sandboxGeneration') = 'integer' AND
    json_extract(${payloadSql}, '${bindingPath}.sandboxGeneration') BETWEEN 1 AND 9007199254740991
  )`;
}

function hostedRuntimePlanReferenceJsonSql(payloadSql: string): string {
  return `(
    json_type(${payloadSql}, '$.runtimeKind') = 'text' AND
    json_extract(${payloadSql}, '$.runtimeKind') = 'daytona' AND
    ${runtimeOutboxBoundedTextSql(`json_extract(${payloadSql}, '$.assignmentPlanRef')`)} AND
    json_type(${payloadSql}, '$.assignmentPlanDigest') = 'text' AND
    length(json_extract(${payloadSql}, '$.assignmentPlanDigest')) = 64 AND
    json_extract(${payloadSql}, '$.assignmentPlanDigest') NOT GLOB '*[^0-9a-f]*' AND
    ${hostedRuntimeBindingJsonSql(payloadSql)}
  )`;
}

function hostedRuntimeTransitionPlanReferenceJsonSql(payloadSql: string): string {
  return `(
    ${hostedRuntimePlanReferenceJsonSql(payloadSql)} AND
    json_type(${payloadSql}, '$.assignmentPlanRuntimeAuthorizationGeneration') = 'integer' AND
    json_extract(${payloadSql}, '$.assignmentPlanRuntimeAuthorizationGeneration')
      BETWEEN 1 AND 9007199254740991 AND
    json_extract(${payloadSql}, '$.assignmentPlanRuntimeAuthorizationGeneration') <
      json_extract(${payloadSql}, '$.runtimeAuthorizationGeneration')
  )`;
}

function hostedRuntimeRecoveryEnsureJsonSql(payloadSql: string): string {
  return `(
    ${runtimeOutboxBoundedTextSql(`json_extract(${payloadSql}, '$.recoveryId')`)} AND
    ${runtimeOutboxBoundedTextSql(`json_extract(${payloadSql}, '$.agentRunId')`)} AND
    ${runtimeOutboxBoundedTextSql(`json_extract(${payloadSql}, '$.fenceOutboxId')`)} AND
    json_type(${payloadSql}, '$.previousRuntimeAuthorizationGeneration') = 'integer' AND
    json_extract(${payloadSql}, '$.previousRuntimeAuthorizationGeneration')
      BETWEEN 1 AND 9007199254740991 AND
    json_extract(${payloadSql}, '$.previousRuntimeAuthorizationGeneration') + 1 =
      json_extract(${payloadSql}, '$.runtimeAuthorizationGeneration') AND
    ${hostedRuntimeBindingJsonSql(payloadSql, "$.previousBinding")} AND
    ${runtimeOutboxBoundedTextSql(`json_extract(${payloadSql}, '$.previousAssignmentPlanRef')`)} AND
    json_type(${payloadSql}, '$.previousAssignmentPlanDigest') = 'text' AND
    length(json_extract(${payloadSql}, '$.previousAssignmentPlanDigest')) = 64 AND
    json_extract(${payloadSql}, '$.previousAssignmentPlanDigest') NOT GLOB '*[^0-9a-f]*' AND
    json_type(
      ${payloadSql}, '$.previousAssignmentPlanRuntimeAuthorizationGeneration'
    ) = 'integer' AND
    json_extract(
      ${payloadSql}, '$.previousAssignmentPlanRuntimeAuthorizationGeneration'
    ) BETWEEN 1 AND 9007199254740991 AND
    json_extract(
      ${payloadSql}, '$.previousAssignmentPlanRuntimeAuthorizationGeneration'
    ) < json_extract(${payloadSql}, '$.previousRuntimeAuthorizationGeneration') AND
    json_extract(${payloadSql}, '$.previousBinding.sessionId') =
      json_extract(${payloadSql}, '$.binding.sessionId') AND
    json_extract(${payloadSql}, '$.previousBinding.runtimeAssignmentId') <>
      json_extract(${payloadSql}, '$.binding.runtimeAssignmentId')
  )`;
}

function hostedRuntimeRecoveryRetireJsonSql(payloadSql: string): string {
  return `(
    ${runtimeOutboxBoundedTextSql(`json_extract(${payloadSql}, '$.recoveryId')`)} AND
    ${runtimeOutboxBoundedTextSql(`json_extract(${payloadSql}, '$.fenceOutboxId')`)} AND
    json_type(${payloadSql}, '$.previousRuntimeAuthorizationGeneration') = 'integer' AND
    json_extract(${payloadSql}, '$.previousRuntimeAuthorizationGeneration')
      BETWEEN 1 AND 9007199254740991 AND
    json_extract(${payloadSql}, '$.previousRuntimeAuthorizationGeneration') + 1 =
      json_extract(${payloadSql}, '$.runtimeAuthorizationGeneration') AND
    ${hostedRuntimeBindingJsonSql(payloadSql, "$.replacementBinding")} AND
    ${runtimeOutboxBoundedTextSql(
      `json_extract(${payloadSql}, '$.replacementAssignmentPlanRef')`
    )} AND
    json_type(${payloadSql}, '$.replacementAssignmentPlanDigest') = 'text' AND
    length(json_extract(${payloadSql}, '$.replacementAssignmentPlanDigest')) = 64 AND
    json_extract(${payloadSql}, '$.replacementAssignmentPlanDigest') NOT GLOB '*[^0-9a-f]*' AND
    json_extract(${payloadSql}, '$.replacementBinding.sessionId') =
      json_extract(${payloadSql}, '$.binding.sessionId') AND
    json_extract(${payloadSql}, '$.replacementBinding.runtimeAssignmentId') <>
      json_extract(${payloadSql}, '$.binding.runtimeAssignmentId')
  )`;
}

function hostedRuntimeRecoverySourceEventSql(): string {
  const previousBindingField = (field: string) => `CASE NEW.kind
    WHEN 'runtime.session.ensure' THEN
      json_extract(NEW.payload_json, '$.previousBinding.${field}')
    ELSE json_extract(NEW.payload_json, '$.binding.${field}') END`;
  const replacementBindingField = (field: string) => `CASE NEW.kind
    WHEN 'runtime.session.ensure' THEN
      json_extract(NEW.payload_json, '$.binding.${field}')
    ELSE json_extract(NEW.payload_json, '$.replacementBinding.${field}') END`;
  const previousAssignmentId = `CASE NEW.kind
    WHEN 'runtime.session.ensure' THEN
      json_extract(NEW.payload_json, '$.previousBinding.runtimeAssignmentId')
    ELSE json_extract(NEW.payload_json, '$.binding.runtimeAssignmentId') END`;
  const replacementAssignmentId = `CASE NEW.kind
    WHEN 'runtime.session.ensure' THEN
      json_extract(NEW.payload_json, '$.binding.runtimeAssignmentId')
    ELSE json_extract(NEW.payload_json, '$.replacementBinding.runtimeAssignmentId') END`;
  const previousPlanRef = `CASE NEW.kind
    WHEN 'runtime.session.ensure' THEN
      json_extract(NEW.payload_json, '$.previousAssignmentPlanRef')
    ELSE json_extract(NEW.payload_json, '$.assignmentPlanRef') END`;
  const previousPlanDigest = `CASE NEW.kind
    WHEN 'runtime.session.ensure' THEN
      json_extract(NEW.payload_json, '$.previousAssignmentPlanDigest')
    ELSE json_extract(NEW.payload_json, '$.assignmentPlanDigest') END`;
  const previousPlanGeneration = `CASE NEW.kind
    WHEN 'runtime.session.ensure' THEN json_extract(
      NEW.payload_json, '$.previousAssignmentPlanRuntimeAuthorizationGeneration'
    ) ELSE json_extract(
      NEW.payload_json, '$.assignmentPlanRuntimeAuthorizationGeneration'
    ) END`;
  const replacementPlanRef = `CASE NEW.kind
    WHEN 'runtime.session.ensure' THEN json_extract(NEW.payload_json, '$.assignmentPlanRef')
    ELSE json_extract(NEW.payload_json, '$.replacementAssignmentPlanRef') END`;
  const replacementPlanDigest = `CASE NEW.kind
    WHEN 'runtime.session.ensure' THEN json_extract(NEW.payload_json, '$.assignmentPlanDigest')
    ELSE json_extract(NEW.payload_json, '$.replacementAssignmentPlanDigest') END`;
  const bindingFields = [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "runtimeAssignmentGeneration",
    "sandboxId",
    "sandboxGeneration",
    "runtimePrincipalId",
  ];
  const previousEventBindingMatches = bindingFields
    .map(
      (field) => `json_extract(event.payload_json, '$.previousBinding.${field}') =
      ${previousBindingField(field)}`
    )
    .join(" AND\n    ");
  const replacementEventBindingMatches = bindingFields
    .map(
      (field) => `json_extract(event.payload_json, '$.replacementBinding.${field}') =
      ${replacementBindingField(field)}`
    )
    .join(" AND\n    ");
  return `(
    (
      NEW.kind = 'runtime.session.ensure' OR
      (NEW.kind = 'runtime.session.retire' AND
       json_extract(NEW.payload_json, '$.reason') = 'assignee-replacement')
    ) AND
    event.type = 'session.hosted-runtime.recovery.requested' AND
    (SELECT count(*) = 12 AND count(*) = count(DISTINCT key)
     FROM json_each(event.payload_json)) AND
    NOT EXISTS (
      SELECT 1 FROM json_each(event.payload_json) WHERE key NOT IN (
        'recoveryId', 'agentRunId', 'fenceOutboxId',
        'previousRuntimeAuthorizationGeneration', 'runtimeAuthorizationGeneration',
        'previousBinding', 'previousAssignmentPlanRef', 'previousAssignmentPlanDigest',
        'previousAssignmentPlanRuntimeAuthorizationGeneration', 'replacementBinding',
        'replacementAssignmentPlanRef', 'replacementAssignmentPlanDigest'
      )
    ) AND
    ${hostedRuntimeBindingJsonSql("event.payload_json", "$.previousBinding")} AND
    ${hostedRuntimeBindingJsonSql("event.payload_json", "$.replacementBinding")} AND
    json_extract(event.payload_json, '$.recoveryId') =
      json_extract(NEW.payload_json, '$.recoveryId') AND
    json_extract(event.payload_json, '$.agentRunId') =
      json_extract(NEW.payload_json, '$.agentRunId') AND
    json_extract(event.payload_json, '$.fenceOutboxId') =
      json_extract(NEW.payload_json, '$.fenceOutboxId') AND
    json_extract(event.payload_json, '$.previousRuntimeAuthorizationGeneration') =
      json_extract(NEW.payload_json, '$.previousRuntimeAuthorizationGeneration') AND
    json_extract(event.payload_json, '$.runtimeAuthorizationGeneration') =
      json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration') AND
    ${previousEventBindingMatches} AND
    ${replacementEventBindingMatches} AND
    json_extract(event.payload_json, '$.previousAssignmentPlanRef') =
      ${previousPlanRef} AND
    json_extract(event.payload_json, '$.previousAssignmentPlanDigest') =
      ${previousPlanDigest} AND
    json_extract(event.payload_json, '$.replacementAssignmentPlanRef') =
      ${replacementPlanRef} AND
    json_extract(event.payload_json, '$.replacementAssignmentPlanDigest') =
      ${replacementPlanDigest} AND
    json_extract(
      event.payload_json, '$.previousAssignmentPlanRuntimeAuthorizationGeneration'
    ) = ${previousPlanGeneration} AND
    EXISTS (
      SELECT 1 FROM sessions session
      JOIN runtime_assignments previous
        ON previous.id = ${previousAssignmentId} AND previous.session_id = session.id
      JOIN hosted_runtime_assignment_plans previous_plan
        ON previous_plan.plan_ref = ${previousPlanRef}
       AND previous_plan.plan_digest = ${previousPlanDigest}
       AND previous_plan.runtime_assignment_id = previous.id
       AND previous_plan.runtime_authorization_generation = ${previousPlanGeneration}
       AND previous_plan.team_id = ${previousBindingField("teamId")}
       AND previous_plan.project_id = ${previousBindingField("projectId")}
       AND previous_plan.session_id = ${previousBindingField("sessionId")}
       AND previous_plan.runtime_assignment_generation =
         ${previousBindingField("runtimeAssignmentGeneration")}
       AND previous_plan.sandbox_id = ${previousBindingField("sandboxId")}
       AND previous_plan.sandbox_generation = ${previousBindingField("sandboxGeneration")}
       AND previous_plan.runtime_principal_id = ${previousBindingField("runtimePrincipalId")}
      JOIN runtime_assignments replacement
        ON replacement.id = ${replacementAssignmentId}
       AND replacement.session_id = session.id
      JOIN hosted_runtime_assignment_plans replacement_plan
        ON replacement_plan.plan_ref = ${replacementPlanRef}
       AND replacement_plan.plan_digest = ${replacementPlanDigest}
       AND replacement_plan.runtime_assignment_id = replacement.id
       AND replacement_plan.runtime_authorization_generation =
         json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
       AND replacement_plan.team_id = ${replacementBindingField("teamId")}
       AND replacement_plan.project_id = ${replacementBindingField("projectId")}
       AND replacement_plan.session_id = ${replacementBindingField("sessionId")}
       AND replacement_plan.runtime_assignment_generation =
         ${replacementBindingField("runtimeAssignmentGeneration")}
       AND replacement_plan.sandbox_id = ${replacementBindingField("sandboxId")}
       AND replacement_plan.sandbox_generation =
         ${replacementBindingField("sandboxGeneration")}
       AND replacement_plan.runtime_principal_id =
         ${replacementBindingField("runtimePrincipalId")}
      JOIN agent_runs run
        ON run.id = json_extract(NEW.payload_json, '$.agentRunId')
       AND run.session_id = session.id AND run.runtime_assignment_id = previous.id
      JOIN runtime_outbox fence
        ON fence.id = json_extract(NEW.payload_json, '$.fenceOutboxId')
       AND fence.session_id = session.id
      WHERE session.id = NEW.session_id AND session.status = 'active'
        AND session.runtime_kind = 'daytona'
        AND session.runtime_authorization_generation =
          json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
        AND session.runtime_authorization_state = 'pending'
        AND previous.runtime_authorization_generation =
          json_extract(NEW.payload_json, '$.previousRuntimeAuthorizationGeneration')
        AND previous.status = 'recovering'
        AND replacement.runtime_authorization_generation =
          json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
        AND replacement.status = 'provisioning'
        AND run.runtime_authorization_generation =
          json_extract(NEW.payload_json, '$.previousRuntimeAuthorizationGeneration')
        AND run.lifecycle IN ('paused', 'agent-work-finished')
        AND fence.kind = 'runtime.authorization.fence' AND fence.status = 'delivered'
        AND json_extract(fence.payload_json, '$.reason') = 'assignee-loss'
        AND json_extract(fence.payload_json, '$.runtimeAuthorizationGeneration') =
          json_extract(NEW.payload_json, '$.previousRuntimeAuthorizationGeneration')
        AND json_extract(fence.payload_json, '$.binding.runtimeAssignmentId') = previous.id
    )
  )`;
}

const RUNTIME_OUTBOX_EVIDENCE_TABLES_SCHEMA_V8 = `
CREATE INDEX runtime_outbox_created_at_idx ON runtime_outbox(created_at_ms);
CREATE INDEX runtime_outbox_dispatch_interlock_acquired_at_idx
  ON runtime_outbox(dispatch_interlock_acquired_at_ms)
  WHERE dispatch_interlock_acquired_at_ms IS NOT NULL;

CREATE TABLE runtime_outbox_settlements (
  outbox_id TEXT NOT NULL REFERENCES runtime_outbox(id) ON DELETE RESTRICT,
  attempt INTEGER NOT NULL CHECK (
    attempt BETWEEN 1 AND 9007199254740991
  ),
  lease_owner TEXT NOT NULL,
  lease_expires_at_ms INTEGER NOT NULL CHECK (
    lease_expires_at_ms BETWEEN 1 AND 9007199254740991
  ),
  dispatch_interlock_attempt INTEGER,
  dispatch_interlock_acquired_at_ms INTEGER,
  outcome TEXT NOT NULL CHECK (outcome IN (
    'acknowledged', 'retryable-failure', 'terminal-failure',
    'lease-expired', 'lease-invalid'
  )),
  error_code TEXT CHECK (error_code IS NULL OR error_code IN (
    'runtime_unavailable', 'runtime_timeout', 'runtime_conflict',
    'runtime_permission_denied', 'runtime_invalid_state', 'runtime_internal'
  )),
  command_source_scope TEXT,
  command_source_key TEXT,
  recorded_at_ms INTEGER NOT NULL CHECK (
    recorded_at_ms BETWEEN 0 AND 9007199254740991
  ),
  PRIMARY KEY (outbox_id, attempt),
  CHECK (
    (dispatch_interlock_attempt IS NULL AND
      dispatch_interlock_acquired_at_ms IS NULL) OR
    (dispatch_interlock_attempt BETWEEN 1 AND attempt AND
      dispatch_interlock_acquired_at_ms IS NOT NULL)
  ),
  CHECK (
    (outcome IN ('acknowledged', 'lease-expired', 'lease-invalid') AND
      error_code IS NULL) OR
    (outcome IN ('retryable-failure', 'terminal-failure') AND error_code IS NOT NULL)
  ),
  CHECK (
    (outcome IN ('lease-expired', 'lease-invalid') AND
      command_source_scope IS NULL AND
      command_source_key IS NULL) OR
    (outcome NOT IN ('lease-expired', 'lease-invalid') AND
      command_source_scope IS NOT NULL AND
      command_source_key IS NOT NULL)
  ),
  FOREIGN KEY (command_source_scope, command_source_key)
    REFERENCES accepted_commands(source_scope, source_key)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE runtime_outbox_supersession_evidence (
  target_outbox_id TEXT PRIMARY KEY
    REFERENCES runtime_outbox(id) ON DELETE RESTRICT,
  source_outbox_id TEXT NOT NULL
    REFERENCES runtime_outbox(id) ON DELETE RESTRICT,
  reason TEXT NOT NULL CHECK (reason IN ('emergency-cutover', 'retired-binding')),
  target_status TEXT NOT NULL CHECK (
    target_status IN ('pending', 'processing', 'failed')
  ),
  target_attempts INTEGER NOT NULL CHECK (
    target_attempts BETWEEN 0 AND 9007199254740991
  ),
  target_lease_owner TEXT,
  target_lease_expires_at_ms INTEGER,
  target_dispatch_interlock_attempt INTEGER,
  target_dispatch_interlock_acquired_at_ms INTEGER,
  source_attempts INTEGER NOT NULL CHECK (
    source_attempts BETWEEN 0 AND 9007199254740991
  ),
  source_lease_owner TEXT,
  source_lease_expires_at_ms INTEGER,
  source_dispatch_interlock_attempt INTEGER,
  source_dispatch_interlock_acquired_at_ms INTEGER,
  command_source_scope TEXT NOT NULL,
  command_source_key TEXT NOT NULL,
  recorded_at_ms INTEGER NOT NULL CHECK (
    recorded_at_ms BETWEEN 0 AND 9007199254740991
  ),
  CHECK (target_outbox_id <> source_outbox_id),
  FOREIGN KEY (command_source_scope, command_source_key)
    REFERENCES accepted_commands(source_scope, source_key)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;
`;

const RUNTIME_OUTBOX_DISPATCH_INTERLOCK_TRIGGERS_SCHEMA_V8 = `
CREATE TRIGGER runtime_outbox_settlements_valid_insert
BEFORE INSERT ON runtime_outbox_settlements
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_outbox outbox
  WHERE outbox.id = NEW.outbox_id
    AND outbox.status = 'processing'
    AND outbox.attempts = NEW.attempt
    AND outbox.lease_owner = NEW.lease_owner
    AND outbox.lease_expires_at_ms = NEW.lease_expires_at_ms
    AND outbox.dispatch_interlock_attempt IS NEW.dispatch_interlock_attempt
    AND outbox.dispatch_interlock_acquired_at_ms IS
      NEW.dispatch_interlock_acquired_at_ms
    AND NEW.recorded_at_ms >= outbox.created_at_ms
    AND (
      NEW.outcome IN ('lease-expired', 'lease-invalid') OR
      NOT EXISTS (
        SELECT 1 FROM accepted_commands accepted
        WHERE accepted.source_scope = NEW.command_source_scope
          AND accepted.source_key = NEW.command_source_key
      )
    )
    AND (
      (
        NEW.outcome = 'lease-expired' AND
        NEW.recorded_at_ms >= NEW.lease_expires_at_ms
      ) OR (
        NEW.outcome = 'lease-invalid' AND
        NEW.lease_expires_at_ms > NEW.recorded_at_ms + 360000
      ) OR (
        NEW.outcome NOT IN ('lease-expired', 'lease-invalid') AND
        NEW.recorded_at_ms < NEW.lease_expires_at_ms AND
        NEW.dispatch_interlock_attempt BETWEEN 1 AND NEW.attempt AND
        NEW.dispatch_interlock_acquired_at_ms IS NOT NULL AND
        NEW.dispatch_interlock_acquired_at_ms <= NEW.recorded_at_ms
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox settlement does not match its exact lease');
END;

CREATE TRIGGER runtime_outbox_settlements_immutable_update
BEFORE UPDATE ON runtime_outbox_settlements
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox settlements are immutable');
END;

CREATE TRIGGER runtime_outbox_settlements_immutable_delete
BEFORE DELETE ON runtime_outbox_settlements
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox settlements are immutable');
END;

CREATE TRIGGER runtime_outbox_supersession_evidence_valid_insert
BEFORE INSERT ON runtime_outbox_supersession_evidence
WHEN NOT EXISTS (
  SELECT 1
  FROM runtime_outbox target
  JOIN runtime_outbox source ON source.id = NEW.source_outbox_id
  JOIN session_events source_event
    ON source_event.session_id = source.session_id
   AND source_event.sequence = source.session_sequence
  JOIN runtime_assignments assignment
    ON assignment.id = json_extract(source.payload_json, '$.runtimeAssignmentId')
   AND assignment.session_id = source.session_id
   AND assignment.generation =
     json_extract(source.payload_json, '$.runtimeAssignmentGeneration')
   AND assignment.sandbox_id = json_extract(source.payload_json, '$.sandboxId')
   AND assignment.sandbox_generation =
     json_extract(source.payload_json, '$.sandboxGeneration')
  JOIN agent_runs run
    ON run.id = json_extract(source.payload_json, '$.agentRunId')
   AND run.session_id = source.session_id
   AND run.runtime_assignment_id = assignment.id
  JOIN sessions session ON session.id = source.session_id
  WHERE target.id = NEW.target_outbox_id
    AND target.session_id = source.session_id
    AND target.status = NEW.target_status
    AND target.attempts = NEW.target_attempts
    AND target.lease_owner IS NEW.target_lease_owner
    AND target.lease_expires_at_ms IS NEW.target_lease_expires_at_ms
    AND target.dispatch_interlock_attempt IS
      NEW.target_dispatch_interlock_attempt
    AND target.dispatch_interlock_acquired_at_ms IS
      NEW.target_dispatch_interlock_acquired_at_ms
    AND source.attempts = NEW.source_attempts
    AND source.lease_owner IS NEW.source_lease_owner
    AND source.lease_expires_at_ms IS NEW.source_lease_expires_at_ms
    AND source.dispatch_interlock_attempt IS
      NEW.source_dispatch_interlock_attempt
    AND source.dispatch_interlock_acquired_at_ms IS
      NEW.source_dispatch_interlock_acquired_at_ms
    AND source.kind = 'runtime.session.retire'
    AND json_extract(source.payload_json, '$.reason') = 'emergency-stop'
    AND source_event.type = 'run.emergency-stop.requested'
    AND source_event.source_scope = CASE NEW.reason
      WHEN 'emergency-cutover' THEN NEW.command_source_scope
      ELSE source_event.source_scope
    END
    AND source_event.source_key = CASE NEW.reason
      WHEN 'emergency-cutover' THEN NEW.command_source_key
      ELSE source_event.source_key
    END
    AND NEW.recorded_at_ms >= target.created_at_ms
    AND NOT EXISTS (
      SELECT 1 FROM accepted_commands accepted
      WHERE accepted.source_scope = NEW.command_source_scope
        AND accepted.source_key = NEW.command_source_key
    )
    AND assignment.status = 'quarantined'
    AND run.lifecycle = 'pausing'
    AND (
      (
        NEW.reason = 'emergency-cutover' AND
        target.session_sequence < source.session_sequence AND
        target.status IN ('pending', 'processing', 'failed') AND
        source.status = 'pending' AND source.attempts = 0 AND
        source.lease_owner IS NULL AND source.lease_expires_at_ms IS NULL AND
        source.dispatch_interlock_attempt IS NULL AND
        source.dispatch_interlock_acquired_at_ms IS NULL AND
        NEW.recorded_at_ms = source.created_at_ms AND
        source_event.occurred_at_ms = source.created_at_ms AND
        json_type(source_event.payload_json, '$.revokeAllRunGrants') = 'true' AND
        json_extract(source_event.payload_json, '$.revokeAllRunGrants') = 1 AND
        json_extract(target.payload_json, '$.runtimeAuthorizationGeneration') <
          json_extract(source.payload_json, '$.runtimeAuthorizationGeneration') AND
        session.runtime_authorization_generation =
          json_extract(source.payload_json, '$.runtimeAuthorizationGeneration') AND
        session.runtime_authorization_state = 'quarantined' AND
        assignment.runtime_authorization_generation =
          json_extract(source.payload_json, '$.runtimeAuthorizationGeneration') AND
        run.runtime_authorization_generation =
          json_extract(source.payload_json, '$.runtimeAuthorizationGeneration')
      ) OR (
        NEW.reason = 'retired-binding' AND
        target.session_sequence > source.session_sequence AND
        target.kind = 'runtime.authorization.fence' AND
        json_extract(target.payload_json, '$.reason') = 'assignee-loss' AND
        json_extract(target.payload_json, '$.runtimeAuthorizationGeneration') >
          json_extract(source.payload_json, '$.runtimeAuthorizationGeneration') AND
        source.status = 'processing' AND
        source.dispatch_interlock_attempt IS NOT NULL AND
        source.dispatch_interlock_attempt <= source.attempts AND
        source.dispatch_interlock_acquired_at_ms IS NOT NULL AND
        source.dispatch_interlock_acquired_at_ms <= NEW.recorded_at_ms AND
        source.lease_expires_at_ms > NEW.recorded_at_ms AND
        session.runtime_authorization_generation >=
          json_extract(target.payload_json, '$.runtimeAuthorizationGeneration') AND
        session.runtime_authorization_state = 'quarantined' AND
        assignment.runtime_authorization_generation =
          json_extract(source.payload_json, '$.runtimeAuthorizationGeneration') AND
        run.runtime_authorization_generation =
          json_extract(source.payload_json, '$.runtimeAuthorizationGeneration')
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox supersession evidence is not exact');
END;

CREATE TRIGGER runtime_outbox_supersession_evidence_immutable_update
BEFORE UPDATE ON runtime_outbox_supersession_evidence
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox supersession evidence is immutable');
END;

CREATE TRIGGER runtime_outbox_supersession_evidence_immutable_delete
BEFORE DELETE ON runtime_outbox_supersession_evidence
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox supersession evidence is immutable');
END;

CREATE TRIGGER accepted_commands_runtime_outbox_evidence
BEFORE INSERT ON accepted_commands
WHEN EXISTS (
  SELECT 1
  FROM runtime_outbox_settlements settlement
  WHERE settlement.command_source_scope = NEW.source_scope
    AND settlement.command_source_key = NEW.source_key
    AND COALESCE((
      json_type(NEW.payload_json) = 'object' AND
      (SELECT count(*) = count(DISTINCT key) FROM json_each(NEW.payload_json)) AND
      (
      (
        settlement.outcome = 'acknowledged' AND
        NEW.command_type = 'runtime.outbox.acknowledge' AND
        NEW.actor_kind = 'system' AND
        NEW.actor_user_id = settlement.lease_owner AND
        json_type(NEW.payload_json, '$.type') = 'text' AND
        json_extract(NEW.payload_json, '$.type') = 'runtime.outbox.acknowledge' AND
        json_type(NEW.payload_json, '$.outboxId') = 'text' AND
        json_extract(NEW.payload_json, '$.outboxId') = settlement.outbox_id AND
        json_type(NEW.payload_json, '$.workerId') = 'text' AND
        json_extract(NEW.payload_json, '$.workerId') = settlement.lease_owner AND
        json_type(NEW.payload_json, '$.expectedAttempt') = 'integer' AND
        json_extract(NEW.payload_json, '$.expectedAttempt') = settlement.attempt AND
        json_type(NEW.payload_json, '$.expectedLeaseExpiresAtMs') = 'integer' AND
        json_extract(NEW.payload_json, '$.expectedLeaseExpiresAtMs') =
          settlement.lease_expires_at_ms AND
        NEW.accepted_at_ms = settlement.recorded_at_ms
      ) OR (
        settlement.outcome IN ('retryable-failure', 'terminal-failure') AND
        NEW.command_type = 'runtime.outbox.fail' AND
        NEW.actor_kind = 'system' AND
        NEW.actor_user_id = settlement.lease_owner AND
        json_type(NEW.payload_json, '$.type') = 'text' AND
        json_extract(NEW.payload_json, '$.type') = 'runtime.outbox.fail' AND
        json_type(NEW.payload_json, '$.outboxId') = 'text' AND
        json_extract(NEW.payload_json, '$.outboxId') = settlement.outbox_id AND
        json_type(NEW.payload_json, '$.workerId') = 'text' AND
        json_extract(NEW.payload_json, '$.workerId') = settlement.lease_owner AND
        json_type(NEW.payload_json, '$.expectedAttempt') = 'integer' AND
        json_extract(NEW.payload_json, '$.expectedAttempt') = settlement.attempt AND
        json_type(NEW.payload_json, '$.expectedLeaseExpiresAtMs') = 'integer' AND
        json_extract(NEW.payload_json, '$.expectedLeaseExpiresAtMs') =
          settlement.lease_expires_at_ms AND
        json_type(NEW.payload_json, '$.errorCode') = 'text' AND
        json_extract(NEW.payload_json, '$.errorCode') = settlement.error_code AND
        json_type(NEW.payload_json, '$.retryable') IN ('true', 'false') AND
        json_extract(NEW.payload_json, '$.retryable') =
          CASE settlement.outcome WHEN 'retryable-failure' THEN 1 ELSE 0 END AND
        NEW.accepted_at_ms = settlement.recorded_at_ms
      )
      )
    ), 0) = 0
) OR EXISTS (
  SELECT 1
  FROM runtime_outbox_supersession_evidence evidence
  JOIN runtime_outbox source ON source.id = evidence.source_outbox_id
  JOIN session_events source_event
    ON source_event.session_id = source.session_id
   AND source_event.sequence = source.session_sequence
  WHERE evidence.command_source_scope = NEW.source_scope
    AND evidence.command_source_key = NEW.source_key
    AND COALESCE((
      json_type(NEW.payload_json) = 'object' AND
      (SELECT count(*) = count(DISTINCT key) FROM json_each(NEW.payload_json)) AND
      (
      (
        evidence.reason = 'emergency-cutover' AND
        NEW.command_type = 'run.emergency-stop' AND
        NEW.actor_kind = 'human' AND
        source_event.actor_kind = NEW.actor_kind AND
        NEW.actor_user_id = source_event.actor_user_id AND
        NEW.actor_display_name = source_event.actor_display_name AND
        source_event.source_scope = NEW.source_scope AND
        source_event.source_key = NEW.source_key AND
        json_type(NEW.payload_json, '$.type') = 'text' AND
        json_extract(NEW.payload_json, '$.type') = 'run.emergency-stop' AND
        json_type(NEW.payload_json, '$.sessionId') = 'text' AND
        json_extract(NEW.payload_json, '$.sessionId') = source.session_id AND
        json_type(NEW.payload_json, '$.agentRunId') = 'text' AND
        json_extract(NEW.payload_json, '$.agentRunId') =
          json_extract(source.payload_json, '$.agentRunId') AND
        json_type(NEW.payload_json, '$.reason') = 'text' AND
        json_extract(NEW.payload_json, '$.reason') =
          json_extract(source_event.payload_json, '$.reason') AND
        json_type(NEW.payload_json, '$.revokeAllRunGrants') = 'true' AND
        json_extract(NEW.payload_json, '$.revokeAllRunGrants') = 1 AND
        json_type(NEW.payload_json, '$.runtimeBinding') = 'object' AND
        (SELECT count(*) = count(DISTINCT key)
         FROM json_each(NEW.payload_json, '$.runtimeBinding')) AND
        json_type(
          NEW.payload_json, '$.runtimeBinding.runtimeAssignmentId'
        ) = 'text' AND
        json_extract(NEW.payload_json, '$.runtimeBinding.runtimeAssignmentId') =
          json_extract(source.payload_json, '$.runtimeAssignmentId') AND
        json_type(
          NEW.payload_json, '$.runtimeBinding.runtimeAssignmentGeneration'
        ) = 'integer' AND
        json_extract(NEW.payload_json, '$.runtimeBinding.runtimeAssignmentGeneration') =
          json_extract(source.payload_json, '$.runtimeAssignmentGeneration') AND
        json_type(NEW.payload_json, '$.runtimeBinding.sandboxId') = 'text' AND
        json_extract(NEW.payload_json, '$.runtimeBinding.sandboxId') =
          json_extract(source.payload_json, '$.sandboxId') AND
        json_type(
          NEW.payload_json, '$.runtimeBinding.sandboxGeneration'
        ) = 'integer' AND
        json_extract(NEW.payload_json, '$.runtimeBinding.sandboxGeneration') =
          json_extract(source.payload_json, '$.sandboxGeneration') AND
        NEW.accepted_at_ms = evidence.recorded_at_ms
      ) OR (
        evidence.reason = 'retired-binding' AND
        NEW.command_type = 'runtime.outbox.acknowledge' AND
        NEW.actor_kind = 'system' AND
        NEW.actor_user_id = evidence.source_lease_owner AND
        json_type(NEW.payload_json, '$.type') = 'text' AND
        json_extract(NEW.payload_json, '$.type') = 'runtime.outbox.acknowledge' AND
        json_type(NEW.payload_json, '$.outboxId') = 'text' AND
        json_extract(NEW.payload_json, '$.outboxId') = evidence.source_outbox_id AND
        json_type(NEW.payload_json, '$.workerId') = 'text' AND
        json_extract(NEW.payload_json, '$.workerId') = evidence.source_lease_owner AND
        json_type(NEW.payload_json, '$.expectedAttempt') = 'integer' AND
        json_extract(NEW.payload_json, '$.expectedAttempt') = evidence.source_attempts AND
        json_type(NEW.payload_json, '$.expectedLeaseExpiresAtMs') = 'integer' AND
        json_extract(NEW.payload_json, '$.expectedLeaseExpiresAtMs') =
          evidence.source_lease_expires_at_ms AND
        NEW.accepted_at_ms = evidence.recorded_at_ms
      )
      )
    ), 0) = 0
)
BEGIN
  SELECT RAISE(ABORT, 'Accepted command does not match Runtime outbox evidence');
END;

CREATE TRIGGER accepted_commands_immutable_update
BEFORE UPDATE ON accepted_commands
BEGIN
  SELECT RAISE(ABORT, 'Accepted commands are immutable');
END;

CREATE TRIGGER accepted_commands_immutable_delete
BEFORE DELETE ON accepted_commands
BEGIN
  SELECT RAISE(ABORT, 'Accepted commands are immutable');
END;

CREATE TRIGGER runtime_outbox_payload_valid_insert
BEFORE INSERT ON runtime_outbox
WHEN CASE
  WHEN json_valid(NEW.payload_json) = 0 THEN 1
  ELSE COALESCE((
    json_type(NEW.payload_json) = 'object' AND
    (SELECT count(*) = count(DISTINCT key) FROM json_each(NEW.payload_json)) AND
    json_type(NEW.payload_json, '$.sessionId') = 'text' AND
    json_extract(NEW.payload_json, '$.sessionId') = NEW.session_id AND
    json_type(NEW.payload_json, '$.runtimeAuthorizationGeneration') = 'integer' AND
    json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
      BETWEEN 1 AND 9007199254740991 AND
    (
      (
        NEW.kind = 'runtime.session.ensure' AND
        (SELECT count(*) FROM json_each(NEW.payload_json)) = 4 AND
        NOT EXISTS (
          SELECT 1 FROM json_each(NEW.payload_json)
          WHERE key NOT IN (
            'sessionId', 'runtimeKind', 'tmuxName', 'runtimeAuthorizationGeneration'
          )
        ) AND
        json_type(NEW.payload_json, '$.runtimeKind') = 'text' AND
        json_extract(NEW.payload_json, '$.runtimeKind') = 'local-tmux' AND
        json_type(NEW.payload_json, '$.tmuxName') = 'text' AND
        length(json_extract(NEW.payload_json, '$.tmuxName')) BETWEEN 1 AND 128 AND
        json_extract(NEW.payload_json, '$.tmuxName') NOT GLOB '*[^a-zA-Z0-9_.-]*'
      ) OR (
        NEW.kind = 'runtime.authorization.fence' AND
        (SELECT count(*) FROM json_each(NEW.payload_json)) = 3 AND
        NOT EXISTS (
          SELECT 1 FROM json_each(NEW.payload_json)
          WHERE key NOT IN ('sessionId', 'reason', 'runtimeAuthorizationGeneration')
        ) AND
        json_type(NEW.payload_json, '$.reason') = 'text' AND
        json_extract(NEW.payload_json, '$.reason') IN ('assignee-loss', 'emergency-stop')
      ) OR (
        NEW.kind = 'runtime.session.retire' AND
        (SELECT count(*) FROM json_each(NEW.payload_json)) = 8 AND
        NOT EXISTS (
          SELECT 1 FROM json_each(NEW.payload_json)
          WHERE key NOT IN (
            'sessionId', 'runtimeAuthorizationGeneration', 'reason', 'agentRunId',
            'runtimeAssignmentId', 'runtimeAssignmentGeneration', 'sandboxId',
            'sandboxGeneration'
          )
        ) AND
        json_type(NEW.payload_json, '$.reason') = 'text' AND
        json_extract(NEW.payload_json, '$.reason') = 'emergency-stop' AND
        json_type(NEW.payload_json, '$.agentRunId') = 'text' AND
        json_type(NEW.payload_json, '$.runtimeAssignmentId') = 'text' AND
        json_type(NEW.payload_json, '$.runtimeAssignmentGeneration') = 'integer' AND
        json_extract(NEW.payload_json, '$.runtimeAssignmentGeneration')
          BETWEEN 1 AND 9007199254740991 AND
        json_type(NEW.payload_json, '$.sandboxId') = 'text' AND
        json_type(NEW.payload_json, '$.sandboxGeneration') = 'integer' AND
        json_extract(NEW.payload_json, '$.sandboxGeneration')
          BETWEEN 1 AND 9007199254740991 AND
        NOT EXISTS (
          SELECT 1
          FROM json_each(json_array(
            json_extract(NEW.payload_json, '$.agentRunId'),
            json_extract(NEW.payload_json, '$.runtimeAssignmentId'),
            json_extract(NEW.payload_json, '$.sandboxId')
          )) identifier
          WHERE NOT ${runtimeOutboxBoundedTextSql("identifier.value")}
        )
      )
    )
  ), 0) = 0
END
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox payload contract is invalid');
END;

CREATE TRIGGER runtime_outbox_dispatch_interlock_valid_insert
BEFORE INSERT ON runtime_outbox
WHEN NOT ${runtimeOutboxBoundedTextSql("NEW.id")} OR
  typeof(NEW.session_sequence) <> 'integer' OR
  NEW.session_sequence NOT BETWEEN 1 AND 9007199254740991 OR
  typeof(NEW.created_at_ms) <> 'integer' OR
  NEW.created_at_ms NOT BETWEEN 0 AND 9007199254740991 OR
  NEW.status <> 'pending' OR
  NEW.attempts <> 0 OR
  NEW.lease_owner IS NOT NULL OR
  NEW.lease_expires_at_ms IS NOT NULL OR
  NEW.dispatch_interlock_attempt IS NOT NULL OR
  NEW.dispatch_interlock_acquired_at_ms IS NOT NULL OR
  NEW.last_error IS NOT NULL OR
  NEW.delivered_at_ms IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox must begin in the exact pending state');
END;

CREATE TRIGGER runtime_outbox_source_event_valid_insert
BEFORE INSERT ON runtime_outbox
WHEN NOT EXISTS (
  SELECT 1
  FROM session_events event
  WHERE event.session_id = NEW.session_id
    AND event.sequence = NEW.session_sequence
    AND event.occurred_at_ms = NEW.created_at_ms
    AND json_type(event.payload_json) = 'object'
    AND (SELECT count(*) = count(DISTINCT key) FROM json_each(event.payload_json))
    AND (
      (
        NEW.kind = 'runtime.session.ensure' AND
        event.type = 'session.started' AND
        json_type(event.payload_json, '$.sessionId') = 'text' AND
        json_extract(event.payload_json, '$.sessionId') = NEW.session_id AND
        json_type(event.payload_json, '$.runtimeKind') = 'text' AND
        json_extract(event.payload_json, '$.runtimeKind') =
          json_extract(NEW.payload_json, '$.runtimeKind') AND
        json_type(event.payload_json, '$.runtimeAuthorizationGeneration') = 'integer' AND
        json_extract(event.payload_json, '$.runtimeAuthorizationGeneration') =
          json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration') AND
        EXISTS (
          SELECT 1 FROM sessions session
          WHERE session.id = NEW.session_id
            AND session.runtime_kind = json_extract(NEW.payload_json, '$.runtimeKind')
            AND session.tmux_name = json_extract(NEW.payload_json, '$.tmuxName')
            AND session.runtime_authorization_generation =
              json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
            AND session.runtime_authorization_state = 'pending'
        )
      ) OR (
        NEW.kind = 'runtime.authorization.fence' AND
        event.type = 'session.runtime-authorization.advanced' AND
        json_type(event.payload_json, '$.reason') = 'text' AND
        json_extract(event.payload_json, '$.reason') =
          json_extract(NEW.payload_json, '$.reason') AND
        json_type(event.payload_json, '$.runtimeAuthorizationGeneration') = 'integer' AND
        json_extract(event.payload_json, '$.runtimeAuthorizationGeneration') =
          json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration') AND
        EXISTS (
          SELECT 1 FROM sessions session
          WHERE session.id = NEW.session_id
            AND session.runtime_authorization_generation =
              json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
            AND session.runtime_authorization_state IN ('pending', 'quarantined')
            AND json_type(event.payload_json, '$.enforcementState') = 'text'
            AND json_extract(event.payload_json, '$.enforcementState') =
              session.runtime_authorization_state
        )
      ) OR (
        NEW.kind = 'runtime.session.retire' AND
        json_extract(NEW.payload_json, '$.reason') = 'emergency-stop' AND
        event.type = 'run.emergency-stop.requested' AND
        json_type(event.payload_json, '$.agentRunId') = 'text' AND
        json_extract(event.payload_json, '$.agentRunId') =
          json_extract(NEW.payload_json, '$.agentRunId') AND
        json_type(event.payload_json, '$.runtimeAuthorizationGeneration') = 'integer' AND
        json_extract(event.payload_json, '$.runtimeAuthorizationGeneration') =
          json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration') AND
        json_type(event.payload_json, '$.reason') = 'text' AND
        json_type(event.payload_json, '$.revokeAllRunGrants') = 'true' AND
        json_extract(event.payload_json, '$.revokeAllRunGrants') = 1 AND
        EXISTS (
          SELECT 1
          FROM sessions session
          JOIN runtime_assignments assignment
            ON assignment.session_id = session.id
          JOIN agent_runs run
            ON run.session_id = session.id
           AND run.runtime_assignment_id = assignment.id
          WHERE session.id = NEW.session_id
            AND session.runtime_authorization_generation =
              json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
            AND session.runtime_authorization_state = 'quarantined'
            AND assignment.id =
              json_extract(NEW.payload_json, '$.runtimeAssignmentId')
            AND assignment.generation =
              json_extract(NEW.payload_json, '$.runtimeAssignmentGeneration')
            AND assignment.sandbox_id =
              json_extract(NEW.payload_json, '$.sandboxId')
            AND assignment.sandbox_generation =
              json_extract(NEW.payload_json, '$.sandboxGeneration')
            AND assignment.runtime_authorization_generation =
              json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
            AND assignment.status = 'quarantined'
            AND run.id = json_extract(NEW.payload_json, '$.agentRunId')
            AND run.runtime_authorization_generation =
              json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
            AND run.lifecycle = 'pausing'
        )
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox source event does not match');
END;

CREATE TRIGGER runtime_outbox_dispatch_interlock_valid_update
BEFORE UPDATE OF dispatch_interlock_attempt, dispatch_interlock_acquired_at_ms
ON runtime_outbox
WHEN COALESCE((
  (
    (NEW.dispatch_interlock_attempt IS NULL) =
      (NEW.dispatch_interlock_acquired_at_ms IS NULL) AND
    NEW.dispatch_interlock_attempt IS OLD.dispatch_interlock_attempt AND
    NEW.dispatch_interlock_acquired_at_ms IS OLD.dispatch_interlock_acquired_at_ms
  ) OR (
    OLD.dispatch_interlock_attempt IS NULL AND
    OLD.dispatch_interlock_acquired_at_ms IS NULL AND
    OLD.status = 'processing' AND NEW.status = 'processing' AND
    NEW.attempts = OLD.attempts AND
    NEW.lease_owner IS OLD.lease_owner AND
    NEW.lease_expires_at_ms IS OLD.lease_expires_at_ms AND
    NEW.dispatch_interlock_attempt = OLD.attempts AND
    NEW.dispatch_interlock_acquired_at_ms >= OLD.created_at_ms AND
    NEW.dispatch_interlock_acquired_at_ms < OLD.lease_expires_at_ms AND
    NOT EXISTS (
      SELECT 1 FROM runtime_outbox_settlements settlement
      WHERE settlement.outbox_id = OLD.id AND settlement.attempt = OLD.attempts
    )
  )
), 0) = 0
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime outbox dispatch interlock transition');
END;

CREATE TRIGGER runtime_outbox_immutable_update
BEFORE UPDATE ON runtime_outbox
WHEN NEW.id IS NOT OLD.id OR
  NEW.session_id IS NOT OLD.session_id OR
  NEW.session_sequence IS NOT OLD.session_sequence OR
  NEW.kind IS NOT OLD.kind OR
  NEW.payload_json IS NOT OLD.payload_json OR
  NEW.created_at_ms IS NOT OLD.created_at_ms
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox identity and work are immutable');
END;

CREATE TRIGGER runtime_outbox_immutable_delete
BEFORE DELETE ON runtime_outbox
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox rows are immutable');
END;

-- runtime_outbox normalizes its source event identity through
-- (session_id, session_sequence), so the referenced event_id must be frozen too.
CREATE TRIGGER runtime_outbox_source_event_immutable_update
BEFORE UPDATE ON session_events
WHEN EXISTS (
  SELECT 1 FROM runtime_outbox outbox
  WHERE outbox.session_id = OLD.session_id
    AND outbox.session_sequence = OLD.sequence
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox source events are immutable');
END;

CREATE TRIGGER runtime_outbox_source_event_immutable_delete
BEFORE DELETE ON session_events
WHEN EXISTS (
  SELECT 1 FROM runtime_outbox outbox
  WHERE outbox.session_id = OLD.session_id
    AND outbox.session_sequence = OLD.sequence
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox source events are immutable');
END;

CREATE TRIGGER runtime_outbox_mutation_valid_update
BEFORE UPDATE ON runtime_outbox
WHEN COALESCE((
  typeof(NEW.attempts) = 'integer' AND
  NEW.attempts BETWEEN 0 AND 9007199254740991 AND
  typeof(NEW.created_at_ms) = 'integer' AND
  NEW.created_at_ms BETWEEN 0 AND 9007199254740991 AND
  (NEW.lease_owner IS NULL OR ${runtimeOutboxBoundedTextSql("NEW.lease_owner")}) AND
  (NEW.lease_expires_at_ms IS NULL OR (
    typeof(NEW.lease_expires_at_ms) = 'integer' AND
    NEW.lease_expires_at_ms BETWEEN 1 AND 9007199254740991
  )) AND
  (NEW.last_error IS NULL OR ${runtimeOutboxBoundedTextSql("NEW.last_error")}) AND
  (NEW.delivered_at_ms IS NULL OR (
    typeof(NEW.delivered_at_ms) = 'integer' AND
    NEW.delivered_at_ms BETWEEN NEW.created_at_ms AND 9007199254740991
  )) AND
  (NEW.dispatch_interlock_attempt IS NULL OR (
    typeof(NEW.dispatch_interlock_attempt) = 'integer' AND
    NEW.dispatch_interlock_attempt BETWEEN 1 AND NEW.attempts
  )) AND
  (NEW.dispatch_interlock_acquired_at_ms IS NULL OR (
    typeof(NEW.dispatch_interlock_acquired_at_ms) = 'integer' AND
    NEW.dispatch_interlock_acquired_at_ms
      BETWEEN NEW.created_at_ms AND 9007199254740991
  )) AND
  (
    -- A processing owner may acquire the interlock or renew one bounded lease.
    -- Other same-status updates must be exact no-ops.
    (
      NEW.status = OLD.status AND
      NEW.attempts = OLD.attempts AND
      NEW.lease_owner IS OLD.lease_owner AND
      NEW.last_error IS OLD.last_error AND
      NEW.delivered_at_ms IS OLD.delivered_at_ms AND
      (
        (
          OLD.status = 'processing' AND
          NEW.lease_expires_at_ms >= OLD.lease_expires_at_ms AND
          NOT EXISTS (
            SELECT 1 FROM runtime_outbox_settlements settlement
            WHERE settlement.outbox_id = OLD.id
              AND settlement.attempt = OLD.attempts
          )
        ) OR (
          OLD.status <> 'processing' AND
          NEW.lease_expires_at_ms IS OLD.lease_expires_at_ms AND
          NEW.dispatch_interlock_attempt IS OLD.dispatch_interlock_attempt AND
          NEW.dispatch_interlock_acquired_at_ms IS
            OLD.dispatch_interlock_acquired_at_ms
        )
      )
    ) OR
    -- Ordinary claim.
    (
      OLD.status = 'pending' AND NEW.status = 'processing' AND
      NEW.attempts = OLD.attempts + 1 AND
      ${runtimeOutboxBoundedTextSql("NEW.lease_owner")} AND
      NEW.lease_expires_at_ms > NEW.created_at_ms AND
      NEW.last_error IS OLD.last_error AND
      NEW.delivered_at_ms IS NULL AND
      NEW.dispatch_interlock_attempt IS OLD.dispatch_interlock_attempt AND
      NEW.dispatch_interlock_acquired_at_ms IS
        OLD.dispatch_interlock_acquired_at_ms
    ) OR
    -- Lease expiry and retry scheduling require an immutable exact-attempt settlement.
    (
      OLD.status = 'processing' AND NEW.status = 'pending' AND
      NEW.attempts = OLD.attempts AND
      NEW.lease_owner IS NULL AND NEW.lease_expires_at_ms IS NULL AND
      NEW.delivered_at_ms IS NULL AND
      NEW.dispatch_interlock_attempt IS OLD.dispatch_interlock_attempt AND
      NEW.dispatch_interlock_acquired_at_ms IS
        OLD.dispatch_interlock_acquired_at_ms AND
      EXISTS (
        SELECT 1 FROM runtime_outbox_settlements settlement
        WHERE settlement.outbox_id = OLD.id
          AND settlement.attempt = OLD.attempts
          AND settlement.lease_owner = OLD.lease_owner
          AND settlement.lease_expires_at_ms = OLD.lease_expires_at_ms
          AND settlement.dispatch_interlock_attempt IS
            OLD.dispatch_interlock_attempt
          AND settlement.dispatch_interlock_acquired_at_ms IS
            OLD.dispatch_interlock_acquired_at_ms
          AND (
            (settlement.outcome IN ('lease-expired', 'lease-invalid') AND
              NEW.last_error IS OLD.last_error) OR
            (settlement.outcome = 'retryable-failure' AND
              NEW.last_error = settlement.error_code)
          )
      )
    ) OR
    -- Adapter acknowledgement is terminal only with exact immutable settlement evidence.
    (
      OLD.status = 'processing' AND NEW.status = 'delivered' AND
      NEW.attempts = OLD.attempts AND
      NEW.lease_owner IS NULL AND NEW.lease_expires_at_ms IS NULL AND
      NEW.last_error IS NULL AND
      NEW.dispatch_interlock_attempt IS OLD.dispatch_interlock_attempt AND
      NEW.dispatch_interlock_acquired_at_ms IS
        OLD.dispatch_interlock_acquired_at_ms AND
      EXISTS (
        SELECT 1 FROM runtime_outbox_settlements settlement
        WHERE settlement.outbox_id = OLD.id
          AND settlement.attempt = OLD.attempts
          AND settlement.lease_owner = OLD.lease_owner
          AND settlement.lease_expires_at_ms = OLD.lease_expires_at_ms
          AND settlement.dispatch_interlock_attempt IS
            OLD.dispatch_interlock_attempt
          AND settlement.dispatch_interlock_acquired_at_ms IS
            OLD.dispatch_interlock_acquired_at_ms
          AND settlement.outcome = 'acknowledged'
          AND settlement.recorded_at_ms = NEW.delivered_at_ms
      )
    ) OR
    -- A permanent adapter failure likewise requires exact settlement evidence.
    (
      OLD.status = 'processing' AND NEW.status = 'failed' AND
      NEW.attempts = OLD.attempts AND
      NEW.lease_owner IS NULL AND NEW.lease_expires_at_ms IS NULL AND
      NEW.last_error IS NOT NULL AND NEW.delivered_at_ms IS NULL AND
      NEW.dispatch_interlock_attempt IS OLD.dispatch_interlock_attempt AND
      NEW.dispatch_interlock_acquired_at_ms IS
        OLD.dispatch_interlock_acquired_at_ms AND
      EXISTS (
        SELECT 1 FROM runtime_outbox_settlements settlement
        WHERE settlement.outbox_id = OLD.id
          AND settlement.attempt = OLD.attempts
          AND settlement.lease_owner = OLD.lease_owner
          AND settlement.lease_expires_at_ms = OLD.lease_expires_at_ms
          AND settlement.dispatch_interlock_attempt IS
            OLD.dispatch_interlock_attempt
          AND settlement.dispatch_interlock_acquired_at_ms IS
            OLD.dispatch_interlock_acquired_at_ms
          AND settlement.outcome = 'terminal-failure'
          AND settlement.error_code = NEW.last_error
      )
    ) OR
    -- Supersession is per-target and cannot be inferred from ambient quarantine.
    (
      OLD.status IN ('pending', 'processing', 'failed') AND
      NEW.status = 'superseded' AND
      NEW.attempts = OLD.attempts AND
      NEW.lease_owner IS NULL AND NEW.lease_expires_at_ms IS NULL AND
      (NEW.last_error IS OLD.last_error OR NEW.last_error IS NULL) AND
      NEW.dispatch_interlock_attempt IS OLD.dispatch_interlock_attempt AND
      NEW.dispatch_interlock_acquired_at_ms IS
        OLD.dispatch_interlock_acquired_at_ms AND
      EXISTS (
        SELECT 1 FROM runtime_outbox_supersession_evidence evidence
        WHERE evidence.target_outbox_id = OLD.id
          AND evidence.target_status = OLD.status
          AND evidence.target_attempts = OLD.attempts
          AND evidence.target_lease_owner IS OLD.lease_owner
          AND evidence.target_lease_expires_at_ms IS OLD.lease_expires_at_ms
          AND evidence.target_dispatch_interlock_attempt IS
            OLD.dispatch_interlock_attempt
          AND evidence.target_dispatch_interlock_acquired_at_ms IS
            OLD.dispatch_interlock_acquired_at_ms
          AND evidence.recorded_at_ms = NEW.delivered_at_ms
          AND (
            evidence.reason = 'emergency-cutover' OR
            (
              evidence.reason = 'retired-binding' AND
              EXISTS (
                SELECT 1
                FROM runtime_outbox source
                JOIN runtime_assignments assignment
                  ON assignment.id =
                    json_extract(source.payload_json, '$.runtimeAssignmentId')
                 AND assignment.session_id = source.session_id
                 AND assignment.generation =
                    json_extract(source.payload_json, '$.runtimeAssignmentGeneration')
                 AND assignment.sandbox_id =
                    json_extract(source.payload_json, '$.sandboxId')
                 AND assignment.sandbox_generation =
                    json_extract(source.payload_json, '$.sandboxGeneration')
                JOIN agent_runs run
                  ON run.id = json_extract(source.payload_json, '$.agentRunId')
                 AND run.session_id = source.session_id
                 AND run.runtime_assignment_id = assignment.id
                WHERE source.id = evidence.source_outbox_id
                  AND source.kind = 'runtime.session.retire'
                  AND json_extract(source.payload_json, '$.reason') = 'emergency-stop'
                  AND source.status = 'delivered'
                  AND source.attempts = evidence.source_attempts
                  AND source.lease_owner IS NULL
                  AND source.lease_expires_at_ms IS NULL
                  AND source.dispatch_interlock_attempt IS
                    evidence.source_dispatch_interlock_attempt
                  AND source.dispatch_interlock_acquired_at_ms IS
                    evidence.source_dispatch_interlock_acquired_at_ms
                  AND source.delivered_at_ms = evidence.recorded_at_ms
                  AND assignment.status = 'retired'
                  AND assignment.retired_at_ms = evidence.recorded_at_ms
                  AND run.lifecycle = 'emergency-stopped'
                  AND run.terminal_at_ms = evidence.recorded_at_ms
                  AND NOT EXISTS (
                    SELECT 1
                    FROM runtime_assignments current_assignment
                    WHERE current_assignment.session_id = source.session_id
                      AND current_assignment.status IN (
                        'provisioning', 'ready', 'checkpointing',
                        'recovering', 'quarantined'
                      )
                  )
              )
            )
          )
      )
    )
  )
), 0) = 0
BEGIN
  SELECT RAISE(ABORT, 'Invalid Runtime outbox state transition');
END;
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
  run_state_revision INTEGER NOT NULL DEFAULT 1 CHECK (run_state_revision >= 1),
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

${AGENT_RUN_SCHEMA}

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

${RUNTIME_RUN_COMMAND_SCHEMA}
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
    options.filename === ":memory:"
      ? options.filename
      : path.resolve(/* turbopackIgnore: true */ options.filename);
  let filename: string | undefined;
  if (resolved !== ":memory:") {
    const parent = path.dirname(/* turbopackIgnore: true */ resolved);
    fs.mkdirSync(/* turbopackIgnore: true */ parent, { recursive: true, mode: 0o700 });
    filename = resolved;
    const descriptor = fs.openSync(/* turbopackIgnore: true */ resolved, "a", 0o600);
    fs.closeSync(descriptor);
    fs.chmodSync(/* turbopackIgnore: true */ resolved, 0o600);
  }

  const db = new Database(resolved);
  secureDatabaseFiles(filename);
  try {
    db.pragma("busy_timeout = 5000");
    db.pragma("foreign_keys = ON");
    db.pragma("recursive_triggers = ON");
    db.pragma("trusted_schema = OFF");

    // Version discovery and first initialization share the same write lock so
    // the Next route bundle and custom server can open a fresh database at the
    // same time without both attempting the migration.
    const initializeOrPrepare = db.transaction((): number => {
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
        db.pragma(`user_version = ${PRE_RUNTIME_START_SCHEMA_VERSION}`);
        return PRE_RUNTIME_START_SCHEMA_VERSION;
      }
      if (applicationId !== APPLICATION_ID) {
        throw new Error("File is not a recognized Team Session database");
      }
      let migratedVersion = currentVersion;
      if (migratedVersion === 1) {
        migrateConversationSchemaV2(db);
        migratedVersion = 2;
      }
      if (migratedVersion === 2) {
        migrateAgentRunSchemaV3(db);
        migratedVersion = 3;
      }
      if (migratedVersion === 3) {
        migrateRuntimeRunCommandSchemaV4(db);
        migratedVersion = 4;
      }
      if (
        migratedVersion !== PRE_RUNTIME_START_SCHEMA_VERSION &&
        migratedVersion !== RUNTIME_START_SCHEMA_VERSION &&
        migratedVersion !== RUNTIME_RECEIPT_FOLLOW_SCHEMA_VERSION &&
        migratedVersion !== RUNTIME_COMPENSATION_SCHEMA_VERSION &&
        migratedVersion !== RUNTIME_ASSIGNMENT_OUTBOX_INTERLOCK_SCHEMA_VERSION &&
        migratedVersion !== HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION &&
        migratedVersion !== PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION &&
        migratedVersion !== CANONICAL_IDENTITY_SCHEMA_VERSION
      ) {
        throw new Error(
          `Unsupported Team Session database schema ${currentVersion}; expected ${SCHEMA_VERSION}`
        );
      }
      if (currentVersion !== migratedVersion) {
        db.pragma(`user_version = ${migratedVersion}`);
      }
      return migratedVersion;
    });
    const preparedVersion = initializeOrPrepare.immediate();
    if (preparedVersion === PRE_RUNTIME_START_SCHEMA_VERSION) {
      migrateRuntimeStartSchemaV5(db);
    }
    const receiptFollowPreparedVersion = db.pragma("user_version", { simple: true }) as number;
    if (receiptFollowPreparedVersion === RUNTIME_START_SCHEMA_VERSION) {
      migrateRuntimeReceiptFollowSchemaV6(db);
    }
    const compensationPreparedVersion = db.pragma("user_version", { simple: true }) as number;
    if (compensationPreparedVersion === RUNTIME_RECEIPT_FOLLOW_SCHEMA_VERSION) {
      migrateRuntimeCompensationSchemaV7(db);
    }
    const assignmentInterlockPreparedVersion = db.pragma("user_version", {
      simple: true,
    }) as number;
    if (assignmentInterlockPreparedVersion === RUNTIME_COMPENSATION_SCHEMA_VERSION) {
      migrateRuntimeAssignmentOutboxInterlockSchemaV8(db);
    }
    const hostedRuntimePreparedVersion = db.pragma("user_version", { simple: true }) as number;
    if (hostedRuntimePreparedVersion === RUNTIME_ASSIGNMENT_OUTBOX_INTERLOCK_SCHEMA_VERSION) {
      migrateHostedRuntimeAssignmentSchemaV9(db);
    }
    const effectActivationPreparedVersion = db.pragma("user_version", { simple: true }) as number;
    if (effectActivationPreparedVersion === HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION) {
      migrateProviderBoundEffectActivationSchemaV10(db);
    }
    const canonicalIdentityPreparedVersion = db.pragma("user_version", {
      simple: true,
    }) as number;
    if (canonicalIdentityPreparedVersion === PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION) {
      migrateCanonicalIdentitySchemaV11(db);
    }

    const applicationId = db.pragma("application_id", { simple: true }) as number;
    if (applicationId !== APPLICATION_ID) {
      throw new Error("File is not a recognized Team Session database");
    }
    const schemaVersion = db.pragma("user_version", { simple: true }) as number;
    if (schemaVersion !== SCHEMA_VERSION) {
      throw new Error(
        `Unsupported Team Session database schema ${schemaVersion}; expected ${SCHEMA_VERSION}`
      );
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
    const recursiveTriggers = db.pragma("recursive_triggers", { simple: true }) as number;
    if (recursiveTriggers !== 1) {
      throw new Error("Team Session database requires recursive trigger enforcement");
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

function migrateAgentRunSchemaV3(db: Database.Database): void {
  db.exec(`
    ALTER TABLE sessions ADD COLUMN run_state_revision INTEGER NOT NULL DEFAULT 1
      CHECK (run_state_revision >= 1);
    ${AGENT_RUN_SCHEMA}
  `);
}

function migrateRuntimeRunCommandSchemaV4(db: Database.Database): void {
  db.exec(RUNTIME_RUN_COMMAND_SCHEMA);
}

function migrateRuntimeStartSchemaV5(db: Database.Database): void {
  // Replacing a parent table while foreign-key enforcement is active records
  // the old parent's implicit deletion even when an exact replacement is
  // installed before commit. Foreign keys are disabled only on this unopened
  // connection, around one exclusive transaction, and every relationship is
  // checked before the schema version can advance.
  db.pragma("foreign_keys = OFF");
  try {
    const migrate = db.transaction(() => {
      const currentVersion = db.pragma("user_version", { simple: true }) as number;
      const applicationId = db.pragma("application_id", { simple: true }) as number;
      if (applicationId !== APPLICATION_ID) {
        throw new Error("File is not a recognized Team Session database");
      }
      if (
        currentVersion === RUNTIME_START_SCHEMA_VERSION ||
        currentVersion === RUNTIME_RECEIPT_FOLLOW_SCHEMA_VERSION ||
        currentVersion === RUNTIME_COMPENSATION_SCHEMA_VERSION ||
        currentVersion === RUNTIME_ASSIGNMENT_OUTBOX_INTERLOCK_SCHEMA_VERSION ||
        currentVersion === HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION ||
        currentVersion === PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION ||
        currentVersion === CANONICAL_IDENTITY_SCHEMA_VERSION
      ) {
        return;
      }
      if (currentVersion !== PRE_RUNTIME_START_SCHEMA_VERSION) {
        throw new Error(
          `Unsupported Team Session database schema ${currentVersion}; expected ${RUNTIME_START_SCHEMA_VERSION}`
        );
      }

      db.exec(RUNTIME_START_SCHEMA_V5);
      const violations = db.pragma("foreign_key_check") as unknown[];
      if (violations.length > 0) {
        throw new Error("Team Session v5 migration failed its foreign key check");
      }
      db.pragma(`user_version = ${RUNTIME_START_SCHEMA_VERSION}`);
    });
    migrate.exclusive();
  } finally {
    db.pragma("foreign_keys = ON");
  }
  const foreignKeys = db.pragma("foreign_keys", { simple: true }) as number;
  if (foreignKeys !== 1) {
    throw new Error("Team Session database requires SQLite foreign key enforcement");
  }
}

function migrateRuntimeReceiptFollowSchemaV6(db: Database.Database): void {
  const migrate = db.transaction(() => {
    const currentVersion = db.pragma("user_version", { simple: true }) as number;
    const applicationId = db.pragma("application_id", { simple: true }) as number;
    if (applicationId !== APPLICATION_ID) {
      throw new Error("File is not a recognized Team Session database");
    }
    if (
      currentVersion === RUNTIME_RECEIPT_FOLLOW_SCHEMA_VERSION ||
      currentVersion === RUNTIME_COMPENSATION_SCHEMA_VERSION ||
      currentVersion === RUNTIME_ASSIGNMENT_OUTBOX_INTERLOCK_SCHEMA_VERSION ||
      currentVersion === HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION ||
      currentVersion === PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION ||
      currentVersion === CANONICAL_IDENTITY_SCHEMA_VERSION
    ) {
      return;
    }
    if (currentVersion !== RUNTIME_START_SCHEMA_VERSION) {
      throw new Error(
        `Unsupported Team Session database schema ${currentVersion}; expected ${RUNTIME_RECEIPT_FOLLOW_SCHEMA_VERSION}`
      );
    }
    addRuntimeReceiptFollowV6Columns(db);
    parkLegacyRuntimeDispatchesForV6Migration(db);
    db.exec(RUNTIME_RECEIPT_FOLLOW_SCHEMA_V6);
    const violations = db.pragma("foreign_key_check") as unknown[];
    if (violations.length > 0) {
      throw new Error("Team Session v6 migration failed its foreign key check");
    }
    db.pragma(`user_version = ${RUNTIME_RECEIPT_FOLLOW_SCHEMA_VERSION}`);
  });
  migrate.immediate();
}

function migrateRuntimeCompensationSchemaV7(db: Database.Database): void {
  const migrate = db.transaction(() => {
    const currentVersion = db.pragma("user_version", { simple: true }) as number;
    const applicationId = db.pragma("application_id", { simple: true }) as number;
    if (applicationId !== APPLICATION_ID) {
      throw new Error("File is not a recognized Team Session database");
    }
    if (
      currentVersion === RUNTIME_COMPENSATION_SCHEMA_VERSION ||
      currentVersion === RUNTIME_ASSIGNMENT_OUTBOX_INTERLOCK_SCHEMA_VERSION ||
      currentVersion === HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION ||
      currentVersion === PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION ||
      currentVersion === CANONICAL_IDENTITY_SCHEMA_VERSION
    ) {
      return;
    }
    if (currentVersion !== RUNTIME_RECEIPT_FOLLOW_SCHEMA_VERSION) {
      throw new Error(
        `Unsupported Team Session database schema ${currentVersion}; expected ${RUNTIME_COMPENSATION_SCHEMA_VERSION}`
      );
    }

    db.exec(RUNTIME_COMPENSATION_TABLES_SCHEMA_V7);
    assertRuntimeLifecycleFencesAreSafeForV7(db);
    backfillRuntimeBindingSafetyFencesV7(db);
    backfillRuntimeCompensationIncidentsV7(db);
    db.exec(RUNTIME_COMPENSATION_TRIGGERS_SCHEMA_V7);
    db.exec(RUNTIME_COMPENSATION_INTEGRATION_TRIGGERS_SCHEMA_V7);
    const violations = db.pragma("foreign_key_check") as unknown[];
    if (violations.length > 0) {
      throw new Error("Team Session v7 migration failed its foreign key check");
    }
    db.pragma(`user_version = ${RUNTIME_COMPENSATION_SCHEMA_VERSION}`);
  });
  migrate.immediate();
}

function migrateRuntimeAssignmentOutboxInterlockSchemaV8(db: Database.Database): void {
  const migrate = db.transaction(() => {
    const currentVersion = db.pragma("user_version", { simple: true }) as number;
    const applicationId = db.pragma("application_id", { simple: true }) as number;
    if (applicationId !== APPLICATION_ID) {
      throw new Error("File is not a recognized Team Session database");
    }
    if (
      currentVersion === RUNTIME_ASSIGNMENT_OUTBOX_INTERLOCK_SCHEMA_VERSION ||
      currentVersion === HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION ||
      currentVersion === PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION ||
      currentVersion === CANONICAL_IDENTITY_SCHEMA_VERSION
    )
      return;
    if (currentVersion !== RUNTIME_COMPENSATION_SCHEMA_VERSION) {
      throw new Error(
        `Unsupported Team Session database schema ${currentVersion}; expected ${RUNTIME_ASSIGNMENT_OUTBOX_INTERLOCK_SCHEMA_VERSION}`
      );
    }

    addRuntimeOutboxDispatchInterlockV8(db);
    ensureAcceptedCommandLedgerV8(db);
    db.exec(RUNTIME_OUTBOX_EVIDENCE_TABLES_SCHEMA_V8);
    db.exec(RUNTIME_OUTBOX_DISPATCH_INTERLOCK_TRIGGERS_SCHEMA_V8);
    const violations = db.pragma("foreign_key_check") as unknown[];
    if (violations.length > 0) {
      throw new Error("Team Session v8 migration failed its foreign key check");
    }
    db.pragma(`user_version = ${RUNTIME_ASSIGNMENT_OUTBOX_INTERLOCK_SCHEMA_VERSION}`);
  });
  migrate.immediate();
}

interface SqliteSchemaArtifactV9 {
  readonly type: "index" | "trigger";
  readonly name: string;
  readonly sql: string;
}

function migrateHostedRuntimeAssignmentSchemaV9(db: Database.Database): void {
  // Both tables are parents of durable lifecycle state. As in v5, replacement
  // is isolated on this unopened connection and followed by a complete FK audit.
  db.pragma("foreign_keys = OFF");
  try {
    const migrate = db.transaction(() => {
      const currentVersion = db.pragma("user_version", { simple: true }) as number;
      const applicationId = db.pragma("application_id", { simple: true }) as number;
      if (applicationId !== APPLICATION_ID) {
        throw new Error("File is not a recognized Team Session database");
      }
      if (
        currentVersion === HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION ||
        currentVersion === PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION ||
        currentVersion === CANONICAL_IDENTITY_SCHEMA_VERSION
      )
        return;
      if (currentVersion !== RUNTIME_ASSIGNMENT_OUTBOX_INTERLOCK_SCHEMA_VERSION) {
        throw new Error(
          `Unsupported Team Session database schema ${currentVersion}; expected ${HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION}`
        );
      }

      assertHostedRuntimeParentRowsAreSafeForV9(db);
      assertRuntimeOutboxPayloadsAreSafeForV8(db);
      assertRuntimeOutboxStatesAreSafeForV8(db);
      assertRuntimeOutboxSourcesAreSafeForV8(db);
      const artifacts = db
        .prepare(
          `SELECT type, name, sql FROM sqlite_schema
           WHERE tbl_name IN ('sessions', 'runtime_assignments')
             AND type IN ('index', 'trigger') AND sql IS NOT NULL
           ORDER BY type, name`
        )
        .all() as SqliteSchemaArtifactV9[];

      db.exec(HOSTED_RUNTIME_PARENT_TABLES_SCHEMA_V9);
      db.pragma("legacy_alter_table = ON");
      db.exec(`
        INSERT INTO sessions_hosted_v9 (
          id, team_id, project_id, name, status, steering_policy,
          access_revision, assignee_revision, supervision_revision, steering_revision,
          control_revision, control_epoch, runtime_authorization_generation,
          runtime_authorization_state, run_state_revision, next_sequence,
          runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms
        )
        SELECT
          id, team_id, project_id, name, status, steering_policy,
          access_revision, assignee_revision, supervision_revision, steering_revision,
          control_revision, control_epoch, runtime_authorization_generation,
          runtime_authorization_state, run_state_revision, next_sequence,
          runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms
        FROM sessions;
        INSERT INTO runtime_assignments_hosted_v9 (
          id, session_id, team_id, project_id, generation, runtime_kind,
          sandbox_id, sandbox_generation, runtime_principal_id,
          runtime_authorization_generation, status, created_at_ms, retired_at_ms
        )
        SELECT
          id, session_id, team_id, project_id, generation, runtime_kind,
          sandbox_id, sandbox_generation, runtime_principal_id,
          runtime_authorization_generation, status, created_at_ms, retired_at_ms
        FROM runtime_assignments;
        ALTER TABLE runtime_assignments RENAME TO runtime_assignments_v8;
        ALTER TABLE sessions RENAME TO sessions_v8;
        ALTER TABLE sessions_hosted_v9 RENAME TO sessions;
        ALTER TABLE runtime_assignments_hosted_v9 RENAME TO runtime_assignments;
        DROP TABLE runtime_assignments_v8;
        DROP TABLE sessions_v8;
      `);
      db.pragma("legacy_alter_table = OFF");
      for (const artifact of artifacts) db.exec(artifact.sql);
      db.exec(`
        DROP INDEX one_current_runtime_assignment_per_session;
        CREATE UNIQUE INDEX one_current_runtime_assignment_per_session
          ON runtime_assignments(session_id)
          WHERE status IN (
            'provisioning', 'ready', 'checkpointing', 'recovering', 'quarantined'
          ) AND NOT (runtime_kind = 'daytona' AND status = 'recovering');
      `);

      db.exec(HOSTED_RUNTIME_ASSIGNMENT_PLANS_SCHEMA_V9);
      db.exec(`
        DROP TRIGGER runtime_outbox_payload_valid_insert;
        DROP TRIGGER runtime_outbox_source_event_valid_insert;
      `);
      db.exec(HOSTED_RUNTIME_OUTBOX_INSERT_TRIGGERS_SCHEMA_V9);
      const violations = db.pragma("foreign_key_check") as unknown[];
      if (violations.length > 0) {
        throw new Error("Team Session v9 migration failed its foreign key check");
      }
      db.pragma(`user_version = ${HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION}`);
    });
    migrate.exclusive();
  } finally {
    db.pragma("legacy_alter_table = OFF");
    db.pragma("foreign_keys = ON");
  }
  if ((db.pragma("foreign_keys", { simple: true }) as number) !== 1) {
    throw new Error("Team Session database requires SQLite foreign key enforcement");
  }
}

function migrateProviderBoundEffectActivationSchemaV10(db: Database.Database): void {
  const migrate = db.transaction(() => {
    const currentVersion = db.pragma("user_version", { simple: true }) as number;
    if (
      currentVersion === PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION ||
      currentVersion === CANONICAL_IDENTITY_SCHEMA_VERSION
    ) {
      return;
    }
    if (currentVersion !== HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION) {
      throw new Error(
        `Unsupported Team Session database schema ${currentVersion}; expected ${HOSTED_RUNTIME_ASSIGNMENT_SCHEMA_VERSION}`
      );
    }

    const legacyHostedPlan = db
      .prepare(
        `SELECT 1
         FROM hosted_runtime_assignment_plans
         LIMIT 1`
      )
      .get();
    if (legacyHostedPlan) {
      throw new Error(
        "Cannot migrate a legacy hosted Runtime Assignment Plan without provider-bound effect policy; retire and reprovision it first"
      );
    }

    // The v9 trigger's exact JSON contract cannot admit the provider-bound
    // policy field. No legacy row can be translated without inventing that
    // security decision, so an empty table is rebuilt under the v10 contract.
    db.exec("DROP TABLE hosted_runtime_assignment_plans");
    db.exec(HOSTED_RUNTIME_ASSIGNMENT_PLANS_SCHEMA_V9);

    addColumnIfMissing(
      db,
      "runtime_authorization_epochs",
      "effect_enforcer_policy_digest",
      `ALTER TABLE runtime_authorization_epochs
         ADD COLUMN effect_enforcer_policy_digest TEXT CHECK (
           effect_enforcer_policy_digest IS NULL OR (
             length(effect_enforcer_policy_digest) = 64 AND
             effect_enforcer_policy_digest = lower(effect_enforcer_policy_digest) AND
             effect_enforcer_policy_digest NOT GLOB '*[^0-9a-f]*'
           )
         )`
    );
    db.exec("DROP TRIGGER runtime_authorization_epochs_immutable_update");
    db.prepare(
      `UPDATE runtime_authorization_epochs
       SET effect_enforcer_policy_digest = effect_enforcer_set_digest
       WHERE effect_enforcer_policy_digest IS NULL`
    ).run();
    db.exec(`
      CREATE TRIGGER runtime_authorization_epochs_immutable_update
      BEFORE UPDATE ON runtime_authorization_epochs
      BEGIN
        SELECT RAISE(ABORT, 'Runtime authorization epochs are immutable');
      END;
    `);

    db.exec(`
      CREATE TABLE runtime_effect_enforcer_set_activations (
        session_id TEXT NOT NULL,
        generation INTEGER NOT NULL CHECK (generation >= 1),
        runtime_assignment_id TEXT NOT NULL,
        runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
        sandbox_id TEXT NOT NULL,
        sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
        runtime_principal_id TEXT NOT NULL,
        activation_kind TEXT NOT NULL CHECK (activation_kind IN ('local-static', 'daytona-provider')),
        effect_enforcer_policy_digest TEXT NOT NULL CHECK (
          length(effect_enforcer_policy_digest) = 64 AND
          effect_enforcer_policy_digest NOT GLOB '*[^0-9a-f]*'
        ),
        effect_enforcer_set_digest TEXT NOT NULL CHECK (
          length(effect_enforcer_set_digest) = 64 AND
          effect_enforcer_set_digest NOT GLOB '*[^0-9a-f]*'
        ),
        assignment_plan_digest TEXT,
        provider_identity_commitment TEXT,
        provider_revision INTEGER CHECK (provider_revision IS NULL OR provider_revision >= 1),
        effect_manifest_binding_digest TEXT,
        activated_at_ms INTEGER NOT NULL CHECK (activated_at_ms >= 0),
        PRIMARY KEY (session_id, generation),
        UNIQUE (
          session_id, generation, runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id,
          effect_enforcer_policy_digest, effect_enforcer_set_digest
        ),
        CHECK (
          (activation_kind = 'local-static' AND
            effect_enforcer_policy_digest = effect_enforcer_set_digest AND
            assignment_plan_digest IS NULL AND provider_identity_commitment IS NULL AND
            provider_revision IS NULL AND effect_manifest_binding_digest IS NULL) OR
          (activation_kind = 'daytona-provider' AND
            assignment_plan_digest IS NOT NULL AND length(assignment_plan_digest) = 64 AND
            assignment_plan_digest NOT GLOB '*[^0-9a-f]*' AND
            provider_identity_commitment IS NOT NULL AND
            length(provider_identity_commitment) = 64 AND
            provider_identity_commitment NOT GLOB '*[^0-9a-f]*' AND
            provider_revision IS NOT NULL AND
            effect_manifest_binding_digest IS NOT NULL AND
            length(effect_manifest_binding_digest) = 64 AND
            effect_manifest_binding_digest NOT GLOB '*[^0-9a-f]*')
        ),
        FOREIGN KEY (
          session_id, generation, runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id
        ) REFERENCES runtime_authorization_epochs(
          session_id, generation, runtime_assignment_id, runtime_assignment_generation,
          sandbox_id, sandbox_generation, runtime_principal_id
        ) ON DELETE RESTRICT
      ) STRICT;

      CREATE TRIGGER runtime_effect_enforcer_set_activations_immutable_update
      BEFORE UPDATE ON runtime_effect_enforcer_set_activations
      BEGIN
        SELECT RAISE(ABORT, 'Runtime effect-enforcer activations are immutable');
      END;

      CREATE TRIGGER runtime_effect_enforcer_set_activations_immutable_delete
      BEFORE DELETE ON runtime_effect_enforcer_set_activations
      BEGIN
        SELECT RAISE(ABORT, 'Runtime effect-enforcer activations are immutable');
      END;
    `);

    db.prepare(
      `INSERT INTO runtime_effect_enforcer_set_activations (
         session_id, generation, runtime_assignment_id, runtime_assignment_generation,
         sandbox_id, sandbox_generation, runtime_principal_id, activation_kind,
         effect_enforcer_policy_digest, effect_enforcer_set_digest,
         assignment_plan_digest, provider_identity_commitment, provider_revision,
         effect_manifest_binding_digest, activated_at_ms
       )
       SELECT epoch.session_id, epoch.generation, epoch.runtime_assignment_id,
              epoch.runtime_assignment_generation, epoch.sandbox_id,
              epoch.sandbox_generation, epoch.runtime_principal_id, 'local-static',
              epoch.effect_enforcer_policy_digest, epoch.effect_enforcer_set_digest,
              NULL, NULL, NULL, NULL, epoch.created_at_ms
       FROM runtime_authorization_epochs epoch
       JOIN runtime_assignments assignment ON assignment.id = epoch.runtime_assignment_id
       WHERE assignment.runtime_kind = 'local-tmux'
         AND epoch.effect_enforcer_policy_digest IS NOT NULL
         AND epoch.effect_enforcer_set_digest IS NOT NULL`
    ).run();

    db.exec(`
      DROP TRIGGER run_policy_revisions_enforcer_set_binding;
      CREATE TRIGGER run_policy_revisions_enforcer_set_binding
      BEFORE INSERT ON run_policy_revisions
      WHEN NEW.required_effect_enforcer_set_digest IS NULL OR NOT EXISTS (
        SELECT 1
        FROM runtime_authorization_epochs epoch
        JOIN runtime_effect_enforcer_set_activations activation
          ON activation.session_id = epoch.session_id
         AND activation.generation = epoch.generation
         AND activation.runtime_assignment_id = epoch.runtime_assignment_id
         AND activation.runtime_assignment_generation = epoch.runtime_assignment_generation
         AND activation.sandbox_id = epoch.sandbox_id
         AND activation.sandbox_generation = epoch.sandbox_generation
         AND activation.runtime_principal_id = epoch.runtime_principal_id
         AND activation.effect_enforcer_policy_digest = epoch.effect_enforcer_policy_digest
        WHERE epoch.session_id = NEW.session_id
          AND epoch.generation = NEW.runtime_authorization_generation
          AND epoch.runtime_assignment_id = NEW.runtime_assignment_id
          AND epoch.runtime_assignment_generation = NEW.runtime_assignment_generation
          AND epoch.sandbox_id = NEW.sandbox_id
          AND epoch.sandbox_generation = NEW.sandbox_generation
          AND epoch.runtime_principal_id = NEW.runtime_principal_id
          AND activation.effect_enforcer_set_digest = NEW.required_effect_enforcer_set_digest
      )
      BEGIN
        SELECT RAISE(ABORT, 'Run policy effect-enforcer set does not match its authorization epoch');
      END;

      DROP TRIGGER runtime_run_commands_enforcer_set_binding;
      CREATE TRIGGER runtime_run_commands_enforcer_set_binding
      BEFORE INSERT ON runtime_run_commands
      WHEN NEW.required_effect_enforcer_set_digest IS NULL OR
        COALESCE(
          json_extract(NEW.command_json, '$.requiredEffectEnforcerSetDigest') =
            NEW.required_effect_enforcer_set_digest,
          0
        ) = 0 OR
        (NEW.operation = 'run.start' AND COALESCE(
          json_extract(NEW.command_json, '$.policy.requiredEffectEnforcerSetDigest') =
            NEW.required_effect_enforcer_set_digest,
          0
        ) = 0) OR NOT EXISTS (
          SELECT 1
          FROM run_policy_revisions policy
          JOIN runtime_authorization_epochs epoch
            ON epoch.session_id = policy.session_id
           AND epoch.generation = policy.runtime_authorization_generation
           AND epoch.runtime_assignment_id = policy.runtime_assignment_id
           AND epoch.runtime_assignment_generation = policy.runtime_assignment_generation
           AND epoch.sandbox_id = policy.sandbox_id
           AND epoch.sandbox_generation = policy.sandbox_generation
           AND epoch.runtime_principal_id = policy.runtime_principal_id
          JOIN runtime_effect_enforcer_set_activations activation
            ON activation.session_id = epoch.session_id
           AND activation.generation = epoch.generation
           AND activation.runtime_assignment_id = epoch.runtime_assignment_id
           AND activation.runtime_assignment_generation = epoch.runtime_assignment_generation
           AND activation.sandbox_id = epoch.sandbox_id
           AND activation.sandbox_generation = epoch.sandbox_generation
           AND activation.runtime_principal_id = epoch.runtime_principal_id
           AND activation.effect_enforcer_policy_digest = epoch.effect_enforcer_policy_digest
          WHERE policy.agent_run_id = NEW.agent_run_id
            AND policy.session_id = NEW.session_id
            AND policy.revision = NEW.run_policy_revision
            AND policy.runtime_assignment_id = NEW.runtime_assignment_id
            AND policy.runtime_assignment_generation = NEW.runtime_assignment_generation
            AND policy.sandbox_id = NEW.sandbox_id
            AND policy.sandbox_generation = NEW.sandbox_generation
            AND policy.runtime_principal_id = NEW.runtime_principal_id
            AND policy.runtime_authorization_generation = NEW.runtime_authorization_generation
            AND policy.required_effect_enforcer_set_digest =
              NEW.required_effect_enforcer_set_digest
            AND activation.effect_enforcer_set_digest = NEW.required_effect_enforcer_set_digest
        )
      BEGIN
        SELECT RAISE(ABORT, 'Runtime command effect-enforcer set does not match policy and epoch');
      END;
    `);

    db.pragma(`user_version = ${PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION}`);
  });
  migrate.exclusive();
}

function migrateCanonicalIdentitySchemaV11(db: Database.Database): void {
  const migrate = db.transaction(() => {
    const currentVersion = db.pragma("user_version", { simple: true }) as number;
    if (currentVersion === CANONICAL_IDENTITY_SCHEMA_VERSION) return;
    if (currentVersion !== PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION) {
      throw new Error(
        `Unsupported Team Session database schema ${currentVersion}; expected ${PROVIDER_BOUND_EFFECT_ACTIVATION_SCHEMA_VERSION}`
      );
    }

    db.exec(CANONICAL_IDENTITY_SCHEMA_V11);
    const violations = db.pragma("foreign_key_check") as unknown[];
    if (violations.length > 0) {
      throw new Error("Team Session v11 migration failed its foreign key check");
    }
    db.pragma(`user_version = ${CANONICAL_IDENTITY_SCHEMA_VERSION}`);
  });
  migrate.exclusive();
}

function assertHostedRuntimeParentRowsAreSafeForV9(db: Database.Database): void {
  const invalidSession = db
    .prepare(
      `SELECT id FROM sessions
       WHERE runtime_kind <> 'local-tmux'
          OR isolation <> 'trusted-shared-host'
          OR tmux_name IS NULL OR length(tmux_name) NOT BETWEEN 1 AND 128
          OR yolo_eligible <> 0
       LIMIT 1`
    )
    .get();
  const invalidAssignment = db
    .prepare(
      `SELECT id FROM runtime_assignments
       WHERE runtime_kind <> 'local-tmux'
       LIMIT 1`
    )
    .get();
  if (invalidSession || invalidAssignment) {
    throw new Error("Team Session v9 migration found poisoned Runtime parent state");
  }
}

const HOSTED_RUNTIME_PARENT_TABLES_SCHEMA_V9 = `
CREATE TABLE sessions_hosted_v9 (
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
  run_state_revision INTEGER NOT NULL DEFAULT 1 CHECK (run_state_revision >= 1),
  next_sequence INTEGER NOT NULL DEFAULT 1 CHECK (next_sequence >= 1),
  runtime_kind TEXT NOT NULL CHECK (runtime_kind IN ('local-tmux', 'daytona')),
  isolation TEXT NOT NULL CHECK (isolation IN ('trusted-shared-host', 'isolated-hosted')),
  tmux_name TEXT CHECK (tmux_name IS NULL OR length(tmux_name) BETWEEN 1 AND 128),
  yolo_eligible INTEGER NOT NULL DEFAULT 0 CHECK (yolo_eligible = 0),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  UNIQUE (team_id, name),
  UNIQUE (tmux_name),
  UNIQUE (id, team_id, project_id),
  CHECK (
    (runtime_kind = 'local-tmux' AND isolation = 'trusted-shared-host' AND tmux_name IS NOT NULL) OR
    (runtime_kind = 'daytona' AND isolation = 'isolated-hosted' AND tmux_name IS NULL)
  ),
  FOREIGN KEY (project_id, team_id) REFERENCES projects(id, team_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE runtime_assignments_hosted_v9 (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation >= 1),
  runtime_kind TEXT NOT NULL CHECK (runtime_kind IN ('local-tmux', 'daytona')),
  sandbox_id TEXT NOT NULL CHECK (length(sandbox_id) BETWEEN 1 AND 300),
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL CHECK (length(runtime_principal_id) BETWEEN 1 AND 300),
  runtime_authorization_generation INTEGER NOT NULL CHECK (runtime_authorization_generation >= 1),
  status TEXT NOT NULL CHECK (status IN (
    'provisioning', 'ready', 'checkpointing', 'recovering',
    'quarantined', 'retired', 'failed'
  )),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  retired_at_ms INTEGER,
  CHECK (
    (status = 'retired' AND retired_at_ms IS NOT NULL) OR
    (status <> 'retired' AND retired_at_ms IS NULL)
  ),
  UNIQUE (session_id, generation),
  UNIQUE (id, session_id),
  UNIQUE (id, generation, sandbox_id, sandbox_generation, runtime_principal_id),
  UNIQUE (id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id),
  FOREIGN KEY (session_id, team_id, project_id)
    REFERENCES sessions(id, team_id, project_id) ON DELETE RESTRICT
) STRICT;
`;

const HOSTED_RUNTIME_ASSIGNMENT_PLANS_SCHEMA_V9 = `
DROP TRIGGER IF EXISTS hosted_runtime_observation_identity_unique_insert;
CREATE TRIGGER hosted_runtime_observation_identity_unique_insert
BEFORE INSERT ON runtime_principal_observation_keys
WHEN EXISTS (
  SELECT 1
  FROM runtime_assignments desired
  JOIN runtime_principal_observation_keys existing
    ON existing.runtime_assignment_id <> NEW.runtime_assignment_id
   AND (
     existing.issuer_key_id = NEW.issuer_key_id OR
     existing.public_key_spki_digest = NEW.public_key_spki_digest
   )
  WHERE desired.id = NEW.runtime_assignment_id AND desired.runtime_kind = 'daytona'
)
BEGIN
  SELECT RAISE(ABORT, 'Hosted Runtime observation identity is already assigned');
END;

CREATE TABLE hosted_runtime_assignment_plans (
  plan_ref TEXT PRIMARY KEY CHECK (length(plan_ref) BETWEEN 1 AND 300),
  plan_digest TEXT NOT NULL UNIQUE CHECK (
    length(plan_digest) = 64 AND plan_digest NOT GLOB '*[^0-9a-f]*'
  ),
  specification_digest TEXT NOT NULL CHECK (
    length(specification_digest) = 64 AND specification_digest NOT GLOB '*[^0-9a-f]*'
  ),
  team_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  runtime_assignment_id TEXT NOT NULL,
  runtime_assignment_generation INTEGER NOT NULL CHECK (runtime_assignment_generation >= 1),
  sandbox_id TEXT NOT NULL,
  sandbox_generation INTEGER NOT NULL CHECK (sandbox_generation >= 1),
  runtime_principal_id TEXT NOT NULL,
  runtime_authorization_generation INTEGER NOT NULL CHECK (runtime_authorization_generation >= 1),
  plan_json TEXT NOT NULL CHECK (json_valid(plan_json) AND json_type(plan_json) = 'object'),
  spec_json TEXT NOT NULL CHECK (json_valid(spec_json) AND json_type(spec_json) = 'object'),
  created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
  UNIQUE (runtime_assignment_id, runtime_authorization_generation),
  UNIQUE (
    runtime_assignment_id, session_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id,
    runtime_authorization_generation
  ),
  FOREIGN KEY (
    runtime_assignment_id, session_id, runtime_assignment_generation,
    sandbox_id, sandbox_generation, runtime_principal_id
  ) REFERENCES runtime_assignments(
    id, session_id, generation, sandbox_id, sandbox_generation, runtime_principal_id
  ) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER hosted_runtime_assignment_plans_valid_insert
BEFORE INSERT ON hosted_runtime_assignment_plans
WHEN NOT EXISTS (
  SELECT 1 FROM runtime_assignments assignment
  JOIN sessions session ON session.id = assignment.session_id
  WHERE assignment.id = NEW.runtime_assignment_id
    AND assignment.session_id = NEW.session_id
    AND assignment.team_id = NEW.team_id
    AND assignment.project_id = NEW.project_id
    AND assignment.generation = NEW.runtime_assignment_generation
    AND assignment.sandbox_id = NEW.sandbox_id
    AND assignment.sandbox_generation = NEW.sandbox_generation
    AND assignment.runtime_principal_id = NEW.runtime_principal_id
    AND assignment.runtime_authorization_generation = NEW.runtime_authorization_generation
    AND assignment.runtime_kind = 'daytona' AND assignment.status IN (
      'provisioning', 'ready', 'checkpointing', 'recovering', 'quarantined'
    )
    AND session.runtime_kind = 'daytona' AND session.isolation = 'isolated-hosted'
    AND session.tmux_name IS NULL AND session.yolo_eligible = 0
    AND (SELECT count(*) = 9 AND count(*) = count(DISTINCT key)
         FROM json_each(NEW.plan_json))
    AND NOT EXISTS (
      SELECT 1 FROM json_each(NEW.plan_json) WHERE key NOT IN (
        'binding', 'runtimeAuthorizationGeneration', 'incarnation',
        'specificationDigest', 'effectEnforcerPolicyDigest',
        'adapterConfigurationRef', 'observation',
        'isolation', 'capabilities'
      )
    )
    AND (SELECT count(*) = 7 AND count(*) = count(DISTINCT key)
         FROM json_each(NEW.spec_json))
    AND NOT EXISTS (
      SELECT 1 FROM json_each(NEW.spec_json) WHERE key NOT IN (
        'binding', 'source', 'harnessRef', 'projectCeiling', 'authorization',
        'checkpointPolicyRef', 'adapterConfigurationRef'
      )
    )
    AND json_extract(NEW.plan_json, '$.binding.teamId') = NEW.team_id
    AND json_extract(NEW.plan_json, '$.binding.projectId') = NEW.project_id
    AND json_extract(NEW.plan_json, '$.binding.sessionId') = NEW.session_id
    AND json_extract(NEW.plan_json, '$.binding.runtimeAssignmentId') = NEW.runtime_assignment_id
    AND json_extract(NEW.plan_json, '$.binding.runtimeAssignmentGeneration') = NEW.runtime_assignment_generation
    AND json_extract(NEW.plan_json, '$.binding.sandboxId') = NEW.sandbox_id
    AND json_extract(NEW.plan_json, '$.binding.sandboxGeneration') = NEW.sandbox_generation
    AND json_extract(NEW.plan_json, '$.binding.runtimePrincipalId') = NEW.runtime_principal_id
    AND json_extract(NEW.plan_json, '$.runtimeAuthorizationGeneration') = NEW.runtime_authorization_generation
    AND json_extract(NEW.plan_json, '$.specificationDigest') = NEW.specification_digest
    AND json_type(NEW.plan_json, '$.effectEnforcerPolicyDigest') = 'text'
    AND length(json_extract(NEW.plan_json, '$.effectEnforcerPolicyDigest')) = 64
    AND json_extract(NEW.plan_json, '$.effectEnforcerPolicyDigest')
          NOT GLOB '*[^0-9a-f]*'
    AND json_extract(NEW.plan_json, '$.effectEnforcerPolicyDigest') =
          json_extract(NEW.spec_json, '$.authorization.effectEnforcerPolicyDigest')
    AND EXISTS (
      SELECT 1 FROM runtime_authorization_epochs epoch
      WHERE epoch.session_id = NEW.session_id
        AND epoch.generation = NEW.runtime_authorization_generation
        AND epoch.runtime_assignment_id = NEW.runtime_assignment_id
        AND epoch.runtime_assignment_generation = NEW.runtime_assignment_generation
        AND epoch.sandbox_id = NEW.sandbox_id
        AND epoch.sandbox_generation = NEW.sandbox_generation
        AND epoch.runtime_principal_id = NEW.runtime_principal_id
        AND epoch.effect_enforcer_policy_digest =
          json_extract(NEW.plan_json, '$.effectEnforcerPolicyDigest')
    )
    AND (SELECT count(*) = 3 AND count(*) = count(DISTINCT key)
         FROM json_each(NEW.plan_json, '$.observation'))
    AND NOT EXISTS (
      SELECT 1 FROM json_each(NEW.plan_json, '$.observation') WHERE key NOT IN (
        'keyProvisioningRef', 'issuerKeyId', 'publicKeySpkiPem'
      )
    )
    AND json_type(NEW.plan_json, '$.observation.keyProvisioningRef') = 'text'
    AND length(json_extract(NEW.plan_json, '$.observation.keyProvisioningRef')) BETWEEN 1 AND 300
    AND json_type(NEW.plan_json, '$.observation.issuerKeyId') = 'text'
    AND length(json_extract(NEW.plan_json, '$.observation.issuerKeyId')) BETWEEN 1 AND 300
    AND json_type(NEW.plan_json, '$.observation.publicKeySpkiPem') = 'text'
    AND EXISTS (
      SELECT 1 FROM runtime_principal_observation_keys observation_key
      WHERE observation_key.runtime_assignment_id = NEW.runtime_assignment_id
        AND observation_key.runtime_authorization_generation =
          NEW.runtime_authorization_generation
        AND observation_key.issuer_key_id =
          json_extract(NEW.plan_json, '$.observation.issuerKeyId')
        AND observation_key.public_key_spki_pem =
          json_extract(NEW.plan_json, '$.observation.publicKeySpkiPem')
    )
    AND NOT EXISTS (
      SELECT 1 FROM hosted_runtime_assignment_plans existing_plan
      WHERE json_extract(
        existing_plan.plan_json, '$.observation.keyProvisioningRef'
      ) = json_extract(NEW.plan_json, '$.observation.keyProvisioningRef')
        AND (
          existing_plan.runtime_assignment_id <> NEW.runtime_assignment_id OR
          existing_plan.runtime_authorization_generation <>
            NEW.runtime_authorization_generation
        )
    )
    AND json_extract(NEW.spec_json, '$.binding.runtimeAssignmentId') = NEW.runtime_assignment_id
    AND json_extract(NEW.spec_json, '$.binding.teamId') = NEW.team_id
    AND json_extract(NEW.spec_json, '$.binding.projectId') = NEW.project_id
    AND json_extract(NEW.spec_json, '$.binding.sessionId') = NEW.session_id
    AND json_extract(NEW.spec_json, '$.binding.runtimeAssignmentGeneration') = NEW.runtime_assignment_generation
    AND json_extract(NEW.spec_json, '$.binding.sandboxId') = NEW.sandbox_id
    AND json_extract(NEW.spec_json, '$.binding.sandboxGeneration') = NEW.sandbox_generation
    AND json_extract(NEW.spec_json, '$.binding.runtimePrincipalId') = NEW.runtime_principal_id
    AND json_extract(NEW.spec_json, '$.authorization.generation') = NEW.runtime_authorization_generation
)
BEGIN
  SELECT RAISE(ABORT, 'Hosted Runtime Assignment Plan binding is invalid');
END;

CREATE TRIGGER hosted_runtime_assignment_plans_immutable_update
BEFORE UPDATE ON hosted_runtime_assignment_plans
BEGIN
  SELECT RAISE(ABORT, 'Hosted Runtime Assignment Plans are immutable');
END;

CREATE TRIGGER hosted_runtime_assignment_plans_immutable_delete
BEFORE DELETE ON hosted_runtime_assignment_plans
BEGIN
  SELECT RAISE(ABORT, 'Hosted Runtime Assignment Plans are immutable');
END;
`;

const HOSTED_RUNTIME_OUTBOX_INSERT_TRIGGERS_SCHEMA_V9 = `
CREATE TRIGGER runtime_outbox_payload_valid_insert
BEFORE INSERT ON runtime_outbox
WHEN CASE
  WHEN json_valid(NEW.payload_json) = 0 THEN 1
  ELSE COALESCE((
    json_type(NEW.payload_json) = 'object' AND
    (SELECT count(*) = count(DISTINCT key) FROM json_each(NEW.payload_json)) AND
    json_type(NEW.payload_json, '$.sessionId') = 'text' AND
    json_extract(NEW.payload_json, '$.sessionId') = NEW.session_id AND
    json_type(NEW.payload_json, '$.runtimeAuthorizationGeneration') = 'integer' AND
    json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
      BETWEEN 1 AND 9007199254740991 AND
    (
      (
        NEW.kind = 'runtime.session.ensure' AND
        (
          (
            (SELECT count(*) FROM json_each(NEW.payload_json)) = 4 AND
            NOT EXISTS (
              SELECT 1 FROM json_each(NEW.payload_json) WHERE key NOT IN (
                'sessionId', 'runtimeKind', 'tmuxName', 'runtimeAuthorizationGeneration'
              )
            ) AND
            json_extract(NEW.payload_json, '$.runtimeKind') = 'local-tmux' AND
            json_type(NEW.payload_json, '$.tmuxName') = 'text' AND
            length(json_extract(NEW.payload_json, '$.tmuxName')) BETWEEN 1 AND 128 AND
            json_extract(NEW.payload_json, '$.tmuxName') NOT GLOB '*[^a-zA-Z0-9_.-]*'
          ) OR (
            ${hostedRuntimePlanReferenceJsonSql("NEW.payload_json")} AND (
              (
                (SELECT count(*) FROM json_each(NEW.payload_json)) = 6 AND
                NOT EXISTS (
                  SELECT 1 FROM json_each(NEW.payload_json) WHERE key NOT IN (
                    'sessionId', 'runtimeKind', 'runtimeAuthorizationGeneration', 'binding',
                    'assignmentPlanRef', 'assignmentPlanDigest'
                  )
                )
              ) OR (
                (SELECT count(*) FROM json_each(NEW.payload_json)) = 14 AND
                NOT EXISTS (
                  SELECT 1 FROM json_each(NEW.payload_json) WHERE key NOT IN (
                    'sessionId', 'runtimeKind', 'runtimeAuthorizationGeneration', 'binding',
                    'assignmentPlanRef', 'assignmentPlanDigest', 'recoveryId', 'agentRunId',
                    'fenceOutboxId', 'previousRuntimeAuthorizationGeneration',
                    'previousBinding', 'previousAssignmentPlanRef',
                    'previousAssignmentPlanDigest',
                    'previousAssignmentPlanRuntimeAuthorizationGeneration'
                  )
                ) AND ${hostedRuntimeRecoveryEnsureJsonSql("NEW.payload_json")}
              )
            )
          )
        )
      ) OR (
        NEW.kind = 'runtime.authorization.fence' AND
        json_extract(NEW.payload_json, '$.reason') IN ('assignee-loss', 'emergency-stop') AND
        (
          (
            (SELECT count(*) FROM json_each(NEW.payload_json)) = 3 AND
            NOT EXISTS (
              SELECT 1 FROM json_each(NEW.payload_json)
              WHERE key NOT IN ('sessionId', 'reason', 'runtimeAuthorizationGeneration')
            )
          ) OR (
            (SELECT count(*) FROM json_each(NEW.payload_json)) = 8 AND
            NOT EXISTS (
              SELECT 1 FROM json_each(NEW.payload_json) WHERE key NOT IN (
                'sessionId', 'reason', 'runtimeAuthorizationGeneration', 'runtimeKind',
                'binding', 'assignmentPlanRef', 'assignmentPlanDigest',
                'assignmentPlanRuntimeAuthorizationGeneration'
              )
            ) AND ${hostedRuntimeTransitionPlanReferenceJsonSql("NEW.payload_json")}
          )
        )
      ) OR (
        NEW.kind = 'runtime.session.retire' AND
        json_extract(NEW.payload_json, '$.reason') IN (
          'emergency-stop', 'assignee-replacement'
        ) AND
        ${runtimeOutboxBoundedTextSql("json_extract(NEW.payload_json, '$.agentRunId')")} AND
        ${runtimeOutboxBoundedTextSql(
          "json_extract(NEW.payload_json, '$.runtimeAssignmentId')"
        )} AND
        json_type(NEW.payload_json, '$.runtimeAssignmentGeneration') = 'integer' AND
        json_extract(NEW.payload_json, '$.runtimeAssignmentGeneration')
          BETWEEN 1 AND 9007199254740991 AND
        ${runtimeOutboxBoundedTextSql("json_extract(NEW.payload_json, '$.sandboxId')")} AND
        json_type(NEW.payload_json, '$.sandboxGeneration') = 'integer' AND
        json_extract(NEW.payload_json, '$.sandboxGeneration') BETWEEN 1 AND 9007199254740991 AND
        (
          (
            (SELECT count(*) FROM json_each(NEW.payload_json)) = 8 AND
            json_extract(NEW.payload_json, '$.reason') = 'emergency-stop' AND
            NOT EXISTS (
              SELECT 1 FROM json_each(NEW.payload_json) WHERE key NOT IN (
                'sessionId', 'runtimeAuthorizationGeneration', 'reason', 'agentRunId',
                'runtimeAssignmentId', 'runtimeAssignmentGeneration', 'sandboxId',
                'sandboxGeneration'
              )
            )
          ) OR (
            (SELECT count(*) FROM json_each(NEW.payload_json)) = 13 AND
            json_extract(NEW.payload_json, '$.reason') = 'emergency-stop' AND
            NOT EXISTS (
              SELECT 1 FROM json_each(NEW.payload_json) WHERE key NOT IN (
                'sessionId', 'runtimeAuthorizationGeneration', 'reason', 'agentRunId',
                'runtimeAssignmentId', 'runtimeAssignmentGeneration', 'sandboxId',
                'sandboxGeneration', 'runtimeKind', 'binding', 'assignmentPlanRef',
                'assignmentPlanDigest', 'assignmentPlanRuntimeAuthorizationGeneration'
              )
            ) AND ${hostedRuntimeTransitionPlanReferenceJsonSql("NEW.payload_json")} AND
            json_extract(NEW.payload_json, '$.runtimeAssignmentId') =
              json_extract(NEW.payload_json, '$.binding.runtimeAssignmentId') AND
            json_extract(NEW.payload_json, '$.runtimeAssignmentGeneration') =
              json_extract(NEW.payload_json, '$.binding.runtimeAssignmentGeneration') AND
            json_extract(NEW.payload_json, '$.sandboxId') =
              json_extract(NEW.payload_json, '$.binding.sandboxId') AND
            json_extract(NEW.payload_json, '$.sandboxGeneration') =
              json_extract(NEW.payload_json, '$.binding.sandboxGeneration')
          ) OR (
            (SELECT count(*) FROM json_each(NEW.payload_json)) = 19 AND
            json_extract(NEW.payload_json, '$.reason') = 'assignee-replacement' AND
            NOT EXISTS (
              SELECT 1 FROM json_each(NEW.payload_json) WHERE key NOT IN (
                'sessionId', 'runtimeAuthorizationGeneration', 'reason', 'agentRunId',
                'runtimeAssignmentId', 'runtimeAssignmentGeneration', 'sandboxId',
                'sandboxGeneration', 'runtimeKind', 'binding', 'assignmentPlanRef',
                'assignmentPlanDigest', 'assignmentPlanRuntimeAuthorizationGeneration',
                'recoveryId', 'fenceOutboxId', 'previousRuntimeAuthorizationGeneration',
                'replacementBinding', 'replacementAssignmentPlanRef',
                'replacementAssignmentPlanDigest'
              )
            ) AND ${hostedRuntimeTransitionPlanReferenceJsonSql("NEW.payload_json")} AND
            ${hostedRuntimeRecoveryRetireJsonSql("NEW.payload_json")} AND
            json_extract(NEW.payload_json, '$.runtimeAssignmentId') =
              json_extract(NEW.payload_json, '$.binding.runtimeAssignmentId') AND
            json_extract(NEW.payload_json, '$.runtimeAssignmentGeneration') =
              json_extract(NEW.payload_json, '$.binding.runtimeAssignmentGeneration') AND
            json_extract(NEW.payload_json, '$.sandboxId') =
              json_extract(NEW.payload_json, '$.binding.sandboxId') AND
            json_extract(NEW.payload_json, '$.sandboxGeneration') =
              json_extract(NEW.payload_json, '$.binding.sandboxGeneration')
          )
        )
      )
    )
  ), 0) = 0
END
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox payload contract is invalid');
END;

CREATE TRIGGER runtime_outbox_source_event_valid_insert
BEFORE INSERT ON runtime_outbox
WHEN NOT EXISTS (
  SELECT 1 FROM session_events event
  WHERE event.session_id = NEW.session_id
    AND event.sequence = NEW.session_sequence
    AND event.occurred_at_ms = NEW.created_at_ms
    AND json_type(event.payload_json) = 'object'
    AND (SELECT count(*) = count(DISTINCT key) FROM json_each(event.payload_json))
    AND (
      (
        NEW.kind = 'runtime.session.ensure' AND event.type = 'session.started' AND
        json_extract(event.payload_json, '$.sessionId') = NEW.session_id AND
        json_extract(event.payload_json, '$.runtimeKind') =
          json_extract(NEW.payload_json, '$.runtimeKind') AND
        json_extract(event.payload_json, '$.runtimeAuthorizationGeneration') =
          json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration') AND
        EXISTS (
          SELECT 1 FROM sessions session
          WHERE session.id = NEW.session_id
            AND session.runtime_kind = json_extract(NEW.payload_json, '$.runtimeKind')
            AND session.runtime_authorization_generation =
              json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
            AND session.runtime_authorization_state = 'pending'
            AND (
              (session.runtime_kind = 'local-tmux' AND session.tmux_name =
                json_extract(NEW.payload_json, '$.tmuxName')) OR
              (session.runtime_kind = 'daytona' AND session.tmux_name IS NULL AND
                EXISTS (
                  SELECT 1 FROM hosted_runtime_assignment_plans plan
                  WHERE plan.plan_ref = json_extract(NEW.payload_json, '$.assignmentPlanRef')
                    AND plan.plan_digest = json_extract(NEW.payload_json, '$.assignmentPlanDigest')
                    AND plan.session_id = NEW.session_id
                    AND plan.runtime_assignment_id =
                      json_extract(NEW.payload_json, '$.binding.runtimeAssignmentId')
                    AND plan.runtime_assignment_generation =
                      json_extract(NEW.payload_json, '$.binding.runtimeAssignmentGeneration')
                    AND plan.sandbox_id = json_extract(NEW.payload_json, '$.binding.sandboxId')
                    AND plan.sandbox_generation =
                      json_extract(NEW.payload_json, '$.binding.sandboxGeneration')
                    AND plan.runtime_principal_id =
                      json_extract(NEW.payload_json, '$.binding.runtimePrincipalId')
                ))
            )
        )
      ) OR ${hostedRuntimeRecoverySourceEventSql()} OR (
        NEW.kind = 'runtime.authorization.fence' AND
        event.type = 'session.runtime-authorization.advanced' AND
        json_extract(event.payload_json, '$.reason') = json_extract(NEW.payload_json, '$.reason') AND
        json_extract(event.payload_json, '$.runtimeAuthorizationGeneration') =
          json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration') AND
        EXISTS (
          SELECT 1 FROM sessions session
          WHERE session.id = NEW.session_id
            AND session.runtime_authorization_generation =
              json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
            AND session.runtime_authorization_state IN ('pending', 'quarantined')
            AND json_extract(event.payload_json, '$.enforcementState') =
              session.runtime_authorization_state
            AND (
              json_type(NEW.payload_json, '$.runtimeKind') IS NULL OR
              (session.runtime_kind = 'daytona' AND EXISTS (
                SELECT 1 FROM hosted_runtime_assignment_plans plan
                JOIN runtime_assignments assignment
                  ON assignment.id = plan.runtime_assignment_id
                WHERE plan.plan_ref = json_extract(NEW.payload_json, '$.assignmentPlanRef')
                  AND plan.plan_digest = json_extract(NEW.payload_json, '$.assignmentPlanDigest')
                  AND plan.team_id = json_extract(NEW.payload_json, '$.binding.teamId')
                  AND plan.project_id = json_extract(NEW.payload_json, '$.binding.projectId')
                  AND plan.session_id = NEW.session_id
                  AND plan.runtime_assignment_id =
                    json_extract(NEW.payload_json, '$.binding.runtimeAssignmentId')
                  AND plan.runtime_assignment_generation =
                    json_extract(NEW.payload_json, '$.binding.runtimeAssignmentGeneration')
                  AND plan.sandbox_id = json_extract(NEW.payload_json, '$.binding.sandboxId')
                  AND plan.sandbox_generation =
                    json_extract(NEW.payload_json, '$.binding.sandboxGeneration')
                  AND plan.runtime_principal_id =
                    json_extract(NEW.payload_json, '$.binding.runtimePrincipalId')
                  AND plan.runtime_authorization_generation = json_extract(
                    NEW.payload_json, '$.assignmentPlanRuntimeAuthorizationGeneration'
                  )
                  AND assignment.runtime_authorization_generation =
                    json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
                  AND assignment.status IN (
                    'provisioning', 'ready', 'checkpointing', 'recovering', 'quarantined'
                  )
                  AND assignment.runtime_kind = 'daytona'
                  AND NOT EXISTS (
                    SELECT 1 FROM hosted_runtime_assignment_plans newer
                    WHERE newer.runtime_assignment_id = plan.runtime_assignment_id
                      AND newer.runtime_authorization_generation >
                        plan.runtime_authorization_generation
                      AND newer.runtime_authorization_generation < json_extract(
                        NEW.payload_json, '$.runtimeAuthorizationGeneration'
                      )
                  )
              ))
            )
        )
      ) OR (
        NEW.kind = 'runtime.session.retire' AND
        event.type = 'run.emergency-stop.requested' AND
        json_extract(event.payload_json, '$.agentRunId') =
          json_extract(NEW.payload_json, '$.agentRunId') AND
        json_extract(event.payload_json, '$.runtimeAuthorizationGeneration') =
          json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration') AND
        json_type(event.payload_json, '$.revokeAllRunGrants') = 'true' AND
        json_extract(event.payload_json, '$.revokeAllRunGrants') = 1 AND
        EXISTS (
          SELECT 1 FROM sessions session
          JOIN runtime_assignments assignment ON assignment.session_id = session.id
          JOIN agent_runs run ON run.session_id = session.id
            AND run.runtime_assignment_id = assignment.id
          WHERE session.id = NEW.session_id
            AND session.runtime_authorization_generation =
              json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
            AND session.runtime_authorization_state = 'quarantined'
            AND assignment.id = json_extract(NEW.payload_json, '$.runtimeAssignmentId')
            AND assignment.generation =
              json_extract(NEW.payload_json, '$.runtimeAssignmentGeneration')
            AND assignment.sandbox_id = json_extract(NEW.payload_json, '$.sandboxId')
            AND assignment.sandbox_generation =
              json_extract(NEW.payload_json, '$.sandboxGeneration')
            AND assignment.runtime_authorization_generation =
              json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
            AND assignment.status = 'quarantined'
            AND run.id = json_extract(NEW.payload_json, '$.agentRunId')
            AND run.runtime_authorization_generation =
              json_extract(NEW.payload_json, '$.runtimeAuthorizationGeneration')
            AND run.lifecycle = 'pausing'
            AND (
              json_type(NEW.payload_json, '$.runtimeKind') IS NULL OR
              (assignment.runtime_kind = 'daytona' AND EXISTS (
                SELECT 1 FROM hosted_runtime_assignment_plans plan
                WHERE plan.plan_ref = json_extract(NEW.payload_json, '$.assignmentPlanRef')
                  AND plan.plan_digest = json_extract(NEW.payload_json, '$.assignmentPlanDigest')
                  AND plan.runtime_assignment_id = assignment.id
                  AND plan.team_id = json_extract(NEW.payload_json, '$.binding.teamId')
                  AND plan.project_id = json_extract(NEW.payload_json, '$.binding.projectId')
                  AND plan.session_id = NEW.session_id
                  AND plan.runtime_assignment_generation =
                    json_extract(NEW.payload_json, '$.binding.runtimeAssignmentGeneration')
                  AND plan.sandbox_id = json_extract(NEW.payload_json, '$.binding.sandboxId')
                  AND plan.sandbox_generation =
                    json_extract(NEW.payload_json, '$.binding.sandboxGeneration')
                  AND plan.runtime_principal_id =
                    json_extract(NEW.payload_json, '$.binding.runtimePrincipalId')
                  AND plan.runtime_authorization_generation = json_extract(
                    NEW.payload_json, '$.assignmentPlanRuntimeAuthorizationGeneration'
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM hosted_runtime_assignment_plans newer
                    WHERE newer.runtime_assignment_id = plan.runtime_assignment_id
                      AND newer.runtime_authorization_generation >
                        plan.runtime_authorization_generation
                      AND newer.runtime_authorization_generation < json_extract(
                        NEW.payload_json, '$.runtimeAuthorizationGeneration'
                      )
                  )
              ))
            )
        )
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'Runtime outbox source event does not match');
END;
`;

function ensureAcceptedCommandLedgerV8(db: Database.Database): void {
  const acceptedCommands = db
    .prepare(
      `SELECT 1 FROM sqlite_schema
       WHERE type = 'table' AND name = 'accepted_commands'`
    )
    .get();
  if (!acceptedCommands) {
    db.exec(`
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
    `);
  }
  const kernelState = db
    .prepare(
      `SELECT 1 FROM sqlite_schema
       WHERE type = 'table' AND name = 'kernel_state'`
    )
    .get();
  if (!kernelState) {
    db.exec(`
      CREATE TABLE kernel_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        next_accepted_sequence INTEGER NOT NULL CHECK (next_accepted_sequence >= 1)
      ) STRICT;
      INSERT INTO kernel_state (singleton, next_accepted_sequence)
      SELECT 1, COALESCE(MAX(accepted_sequence), 0) + 1 FROM accepted_commands;
    `);
  }
}

function addRuntimeOutboxDispatchInterlockV8(db: Database.Database): void {
  const outboxTable = db
    .prepare(
      `SELECT 1 FROM sqlite_schema
       WHERE type = 'table' AND name = 'runtime_outbox'`
    )
    .get();
  if (!outboxTable) {
    // The original v2 Session schema predates the assignment outbox. Build the
    // current additive table here so a genuine v2 database reaches the same v8
    // invariant as a fresh install.
    db.exec(`
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
        dispatch_interlock_attempt INTEGER CHECK (
          dispatch_interlock_attempt IS NULL OR (
            dispatch_interlock_attempt >= 1 AND dispatch_interlock_attempt <= attempts
          )
        ),
        dispatch_interlock_acquired_at_ms INTEGER CHECK (
          dispatch_interlock_acquired_at_ms IS NULL OR
          dispatch_interlock_acquired_at_ms >= created_at_ms
        ),
        last_error TEXT,
        created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
        delivered_at_ms INTEGER,
        UNIQUE (session_id, session_sequence, kind),
        FOREIGN KEY (session_id, session_sequence)
          REFERENCES session_events(session_id, sequence) ON DELETE RESTRICT
      ) STRICT;
    `);
  }
  addColumnIfMissing(
    db,
    "runtime_outbox",
    "dispatch_interlock_attempt",
    `ALTER TABLE runtime_outbox
       ADD COLUMN dispatch_interlock_attempt INTEGER CHECK (
         dispatch_interlock_attempt IS NULL OR (
           dispatch_interlock_attempt >= 1 AND dispatch_interlock_attempt <= attempts
         )
       )`
  );
  addColumnIfMissing(
    db,
    "runtime_outbox",
    "dispatch_interlock_acquired_at_ms",
    `ALTER TABLE runtime_outbox
       ADD COLUMN dispatch_interlock_acquired_at_ms INTEGER CHECK (
         dispatch_interlock_acquired_at_ms IS NULL OR
         dispatch_interlock_acquired_at_ms >= created_at_ms
       )`
  );

  assertRuntimeOutboxPayloadsAreSafeForV8(db);
  assertRuntimeOutboxStatesAreSafeForV8(db);
  assertRuntimeOutboxSourcesAreSafeForV8(db);

  // v7 had no assignment point-of-no-return marker. Every non-terminal row that has
  // already been attempted is therefore ambiguous and may only be reconciled.
  // Using the immutable creation time avoids inventing a false observation
  // time while still preserving the fact that dispatch may have happened.
  db.prepare(
    `UPDATE runtime_outbox
     SET dispatch_interlock_attempt = attempts,
         dispatch_interlock_acquired_at_ms = created_at_ms
     WHERE status IN ('pending', 'processing') AND attempts > 0
       AND dispatch_interlock_attempt IS NULL
       AND dispatch_interlock_acquired_at_ms IS NULL`
  ).run();
}

interface RuntimeOutboxMigrationRow {
  id: string;
  session_id: string;
  kind: string;
  payload_json: string;
}

function assertRuntimeOutboxPayloadsAreSafeForV8(db: Database.Database): void {
  const rows = db
    .prepare(
      `SELECT id, session_id, kind, payload_json
       FROM runtime_outbox
       ORDER BY rowid`
    )
    .all() as RuntimeOutboxMigrationRow[];
  for (const row of rows) {
    const sqliteShape = db
      .prepare(
        `SELECT
           json_valid(?) = 1 AND
           json_type(?) = 'object' AND
           (SELECT count(*) = count(DISTINCT key) FROM json_each(?)) AND
           json_type(?, '$.sessionId') = 'text' AND
           json_type(?, '$.runtimeAuthorizationGeneration') = 'integer' AND
           CASE ?
             WHEN 'runtime.session.ensure' THEN
               json_type(?, '$.runtimeKind') = 'text' AND
               json_type(?, '$.tmuxName') = 'text'
             WHEN 'runtime.authorization.fence' THEN
               json_type(?, '$.reason') = 'text'
             WHEN 'runtime.session.retire' THEN
               json_type(?, '$.reason') = 'text' AND
               json_type(?, '$.agentRunId') = 'text' AND
               json_type(?, '$.runtimeAssignmentId') = 'text' AND
               json_type(?, '$.runtimeAssignmentGeneration') = 'integer' AND
               json_type(?, '$.sandboxId') = 'text' AND
               json_type(?, '$.sandboxGeneration') = 'integer'
             ELSE 0
           END AS valid`
      )
      .get(
        row.payload_json,
        row.payload_json,
        row.payload_json,
        row.payload_json,
        row.payload_json,
        row.kind,
        row.payload_json,
        row.payload_json,
        row.payload_json,
        row.payload_json,
        row.payload_json,
        row.payload_json,
        row.payload_json,
        row.payload_json,
        row.payload_json
      ) as { valid: number };
    if (sqliteShape.valid !== 1) {
      throw invalidRuntimeOutboxPayloadForMigration(row.id);
    }
    let payload: unknown;
    try {
      payload = JSON.parse(row.payload_json);
    } catch {
      throw invalidRuntimeOutboxPayloadForMigration(row.id);
    }
    if (!isRuntimeOutboxPayloadForMigration(row, payload)) {
      throw invalidRuntimeOutboxPayloadForMigration(row.id);
    }
  }
}

function isRuntimeOutboxPayloadForMigration(
  row: RuntimeOutboxMigrationRow,
  payload: unknown
): boolean {
  if (!isRuntimeOutboxPayloadRecord(payload) || payload.sessionId !== row.session_id) return false;
  if (!isPositiveSafeInteger(payload.runtimeAuthorizationGeneration)) return false;

  switch (row.kind) {
    case "runtime.session.ensure":
      return (
        hasExactRuntimeOutboxPayloadKeys(payload, [
          "sessionId",
          "runtimeKind",
          "tmuxName",
          "runtimeAuthorizationGeneration",
        ]) &&
        payload.runtimeKind === "local-tmux" &&
        isValidTmuxSessionName(payload.tmuxName)
      );
    case "runtime.authorization.fence":
      return (
        hasExactRuntimeOutboxPayloadKeys(payload, [
          "sessionId",
          "reason",
          "runtimeAuthorizationGeneration",
        ]) &&
        (payload.reason === "assignee-loss" || payload.reason === "emergency-stop")
      );
    case "runtime.session.retire":
      return (
        hasExactRuntimeOutboxPayloadKeys(payload, [
          "sessionId",
          "runtimeAuthorizationGeneration",
          "reason",
          "agentRunId",
          "runtimeAssignmentId",
          "runtimeAssignmentGeneration",
          "sandboxId",
          "sandboxGeneration",
        ]) &&
        payload.reason === "emergency-stop" &&
        isRuntimeOutboxMigrationIdentifier(payload.agentRunId) &&
        isRuntimeOutboxMigrationIdentifier(payload.runtimeAssignmentId) &&
        isPositiveSafeInteger(payload.runtimeAssignmentGeneration) &&
        isRuntimeOutboxMigrationIdentifier(payload.sandboxId) &&
        isPositiveSafeInteger(payload.sandboxGeneration)
      );
    default:
      return false;
  }
}

function isRuntimeOutboxPayloadRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactRuntimeOutboxPayloadKeys(
  payload: Record<string, unknown>,
  expectedKeys: readonly string[]
): boolean {
  const actualKeys = Object.keys(payload);
  return (
    actualKeys.length === expectedKeys.length &&
    expectedKeys.every((key) => Object.prototype.hasOwnProperty.call(payload, key))
  );
}

function isPositiveSafeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 1;
}

function isRuntimeOutboxMigrationIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    Buffer.byteLength(value, "utf8") <= 300 &&
    value.trim() === value &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function assertRuntimeOutboxStatesAreSafeForV8(db: Database.Database): void {
  const invalid = db
    .prepare(
      `SELECT id
       FROM runtime_outbox
       WHERE NOT (
         ${runtimeOutboxBoundedTextSql("id")} AND
         typeof(session_sequence) = 'integer' AND
         session_sequence BETWEEN 1 AND 9007199254740991 AND
         typeof(attempts) = 'integer' AND
         attempts BETWEEN 0 AND 9007199254740991 AND
         typeof(created_at_ms) = 'integer' AND
         created_at_ms BETWEEN 0 AND 9007199254740991 AND
         (last_error IS NULL OR ${runtimeOutboxBoundedTextSql("last_error")}) AND
         CASE status
           WHEN 'pending' THEN
             lease_owner IS NULL AND lease_expires_at_ms IS NULL AND
             delivered_at_ms IS NULL
           WHEN 'processing' THEN
             attempts >= 1 AND ${runtimeOutboxBoundedTextSql("lease_owner")} AND
             typeof(lease_expires_at_ms) = 'integer' AND
             lease_expires_at_ms BETWEEN MAX(created_at_ms, 1) AND 9007199254740991 AND
             delivered_at_ms IS NULL
           WHEN 'delivered' THEN
             attempts >= 1 AND lease_owner IS NULL AND lease_expires_at_ms IS NULL AND
             last_error IS NULL AND typeof(delivered_at_ms) = 'integer' AND
             delivered_at_ms BETWEEN created_at_ms AND 9007199254740991
           WHEN 'superseded' THEN
             lease_owner IS NULL AND lease_expires_at_ms IS NULL AND
             typeof(delivered_at_ms) = 'integer' AND
             delivered_at_ms BETWEEN created_at_ms AND 9007199254740991
           WHEN 'failed' THEN
             attempts >= 1 AND lease_owner IS NULL AND lease_expires_at_ms IS NULL AND
             last_error IS NOT NULL AND delivered_at_ms IS NULL
           ELSE 0
         END
       )
       ORDER BY rowid
       LIMIT 1`
    )
    .get() as { id: unknown } | undefined;
  if (invalid) {
    throw new Error(
      `Cannot migrate Runtime outbox ${safeRuntimeOutboxMigrationIdentity(
        invalid.id
      )}: durable state is invalid`
    );
  }
}

function assertRuntimeOutboxSourcesAreSafeForV8(db: Database.Database): void {
  const invalid = db
    .prepare(
      `SELECT outbox.id
       FROM runtime_outbox outbox
       WHERE NOT EXISTS (
         SELECT 1
         FROM session_events event
         WHERE event.session_id = outbox.session_id
           AND event.sequence = outbox.session_sequence
           AND event.occurred_at_ms = outbox.created_at_ms
           AND json_type(event.payload_json) = 'object'
           AND (SELECT count(*) = count(DISTINCT key) FROM json_each(event.payload_json))
           AND (
             (
               outbox.kind = 'runtime.session.ensure' AND
               event.type = 'session.started' AND
               json_type(event.payload_json, '$.sessionId') = 'text' AND
               json_extract(event.payload_json, '$.sessionId') = outbox.session_id AND
               json_type(event.payload_json, '$.runtimeKind') = 'text' AND
               json_extract(event.payload_json, '$.runtimeKind') =
                 json_extract(outbox.payload_json, '$.runtimeKind') AND
               json_type(
                 event.payload_json, '$.runtimeAuthorizationGeneration'
               ) = 'integer' AND
               json_extract(event.payload_json, '$.runtimeAuthorizationGeneration') =
                 json_extract(outbox.payload_json, '$.runtimeAuthorizationGeneration')
             ) OR (
               outbox.kind = 'runtime.authorization.fence' AND
               event.type = 'session.runtime-authorization.advanced' AND
               json_type(event.payload_json, '$.reason') = 'text' AND
               json_extract(event.payload_json, '$.reason') =
                 json_extract(outbox.payload_json, '$.reason') AND
               json_type(
                 event.payload_json, '$.runtimeAuthorizationGeneration'
               ) = 'integer' AND
               json_extract(event.payload_json, '$.runtimeAuthorizationGeneration') =
                 json_extract(outbox.payload_json, '$.runtimeAuthorizationGeneration') AND
               json_type(event.payload_json, '$.enforcementState') = 'text' AND
               json_extract(event.payload_json, '$.enforcementState') IN (
                 'pending', 'quarantined'
               )
             ) OR (
               outbox.kind = 'runtime.session.retire' AND
               json_extract(outbox.payload_json, '$.reason') = 'emergency-stop' AND
               event.type = 'run.emergency-stop.requested' AND
               json_type(event.payload_json, '$.agentRunId') = 'text' AND
               json_extract(event.payload_json, '$.agentRunId') =
                 json_extract(outbox.payload_json, '$.agentRunId') AND
               json_type(
                 event.payload_json, '$.runtimeAuthorizationGeneration'
               ) = 'integer' AND
               json_extract(event.payload_json, '$.runtimeAuthorizationGeneration') =
                 json_extract(outbox.payload_json, '$.runtimeAuthorizationGeneration') AND
               json_type(event.payload_json, '$.reason') = 'text' AND
               json_type(event.payload_json, '$.revokeAllRunGrants') = 'true' AND
               json_extract(event.payload_json, '$.revokeAllRunGrants') = 1 AND
               EXISTS (
                 SELECT 1
                 FROM runtime_assignments assignment
                 JOIN agent_runs run
                   ON run.runtime_assignment_id = assignment.id
                  AND run.session_id = assignment.session_id
                 WHERE assignment.id =
                     json_extract(outbox.payload_json, '$.runtimeAssignmentId')
                   AND assignment.session_id = outbox.session_id
                   AND assignment.generation =
                     json_extract(outbox.payload_json, '$.runtimeAssignmentGeneration')
                   AND assignment.sandbox_id =
                     json_extract(outbox.payload_json, '$.sandboxId')
                   AND assignment.sandbox_generation =
                     json_extract(outbox.payload_json, '$.sandboxGeneration')
                   AND run.id = json_extract(outbox.payload_json, '$.agentRunId')
               )
             )
           )
       )
       ORDER BY outbox.rowid
       LIMIT 1`
    )
    .get() as { id: unknown } | undefined;
  if (invalid) {
    throw new Error(
      `Cannot migrate Runtime outbox ${safeRuntimeOutboxMigrationIdentity(
        invalid.id
      )}: source event is invalid`
    );
  }
}

function invalidRuntimeOutboxPayloadForMigration(rowId: unknown): Error {
  return new Error(
    `Cannot migrate Runtime outbox ${safeRuntimeOutboxMigrationIdentity(
      rowId
    )}: payload contract is invalid`
  );
}

function safeRuntimeOutboxMigrationIdentity(rowId: unknown): string {
  return typeof rowId === "string" && /^[a-zA-Z0-9_.:-]{1,300}$/.test(rowId)
    ? rowId
    : `sha256:${createHash("sha256").update(String(rowId)).digest("hex").slice(0, 16)}`;
}

function assertRuntimeLifecycleFencesAreSafeForV7(db: Database.Database): void {
  const invalid = db
    .prepare(
      `SELECT receipt.id
       FROM runtime_run_command_receipts receipt
       WHERE (receipt.outcome = 'enforced' OR
           (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced'))
         AND (
           COALESCE(json_type(
             receipt.receipt_json,
             CASE WHEN receipt.outcome = 'duplicate'
               THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
           ) = 'integer', 0) = 0 OR
           json_extract(
             receipt.receipt_json,
             CASE WHEN receipt.outcome = 'duplicate'
               THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
           ) < 1 OR
           json_extract(
             receipt.receipt_json,
             CASE WHEN receipt.outcome = 'duplicate'
               THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
           ) > 9007199254740991
         )
       LIMIT 1`
    )
    .get();
  if (invalid) {
    throw new Error("Team Session v7 migration found an unsafe Runtime enforcement fence");
  }
}

function backfillRuntimeBindingSafetyFencesV7(db: Database.Database): void {
  db.exec(`
    INSERT INTO runtime_binding_safety_fences (
      team_id, project_id, session_id, runtime_assignment_id,
      runtime_assignment_generation, sandbox_id, sandbox_generation,
      runtime_principal_id, allocated_fence, updated_at_ms
    )
    SELECT
      assignment.team_id,
      assignment.project_id,
      assignment.session_id,
      assignment.id,
      assignment.generation,
      assignment.sandbox_id,
      assignment.sandbox_generation,
      assignment.runtime_principal_id,
      MAX(
        1,
        session.control_epoch,
        session.steering_revision,
        session.runtime_authorization_generation,
        COALESCE((
          SELECT MAX(run.state_version)
          FROM agent_runs run
          WHERE run.session_id = assignment.session_id
            AND run.runtime_assignment_id = assignment.id
        ), 1),
        COALESCE((
          SELECT MAX(command.target_run_state_version)
          FROM runtime_run_commands command
          WHERE command.session_id = assignment.session_id
            AND command.runtime_assignment_id = assignment.id
            AND command.runtime_assignment_generation = assignment.generation
            AND command.sandbox_id = assignment.sandbox_id
            AND command.sandbox_generation = assignment.sandbox_generation
            AND command.runtime_principal_id = assignment.runtime_principal_id
        ), 1),
        COALESCE((
          SELECT MAX(json_extract(
            receipt.receipt_json,
            CASE WHEN receipt.outcome = 'duplicate'
              THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
          ))
          FROM runtime_run_command_receipts receipt
          JOIN runtime_run_commands command ON command.id = receipt.command_id
          WHERE command.session_id = assignment.session_id
            AND command.runtime_assignment_id = assignment.id
            AND command.runtime_assignment_generation = assignment.generation
            AND command.sandbox_id = assignment.sandbox_id
            AND command.sandbox_generation = assignment.sandbox_generation
            AND command.runtime_principal_id = assignment.runtime_principal_id
            AND (receipt.outcome = 'enforced' OR
              (receipt.outcome = 'duplicate' AND receipt.original_outcome = 'enforced'))
        ), 1)
      ),
      MAX(assignment.created_at_ms, session.created_at_ms)
    FROM runtime_assignments assignment
    JOIN sessions session ON session.id = assignment.session_id;
  `);
}

function backfillRuntimeCompensationIncidentsV7(db: Database.Database): void {
  const alreadyApplied = db
    .prepare(
      `SELECT dispatch.command_id
       FROM runtime_run_command_dispatch dispatch
       JOIN runtime_run_command_effects effect ON effect.command_id = dispatch.command_id
       WHERE dispatch.status = 'compensating'
       LIMIT 1`
    )
    .get();
  if (alreadyApplied) {
    throw new Error(
      "Team Session v7 migration found a compensating dispatch with an applied lifecycle effect"
    );
  }

  const candidates = db
    .prepare(
      `SELECT
         command.id AS source_command_id,
         receipt.id AS source_receipt_id,
         command.session_id,
         assignment.team_id,
         assignment.project_id,
         command.agent_run_id,
         command.run_policy_revision,
         command.runtime_assignment_id,
         command.runtime_assignment_generation,
         command.sandbox_id,
         command.sandbox_generation,
         command.runtime_principal_id,
         command.runtime_authorization_generation,
         command.command_digest AS source_command_digest,
         command.authority_digest AS lifecycle_command_claims_digest,
         receipt.receipt_digest AS lifecycle_receipt_digest,
         command.required_effect_enforcer_set_digest AS source_required_digest,
         receipt.required_effect_enforcer_set_digest AS receipt_required_digest,
         receipt.enforcement_subject_digest AS lifecycle_enforcement_subject_digest,
         receipt.aggregate_proof_digest AS lifecycle_aggregate_proof_digest,
         receipt.proof_verified_at_ms AS source_proof_verified_at_ms,
         receipt.received_at_ms,
         json_extract(
           receipt.receipt_json,
           CASE WHEN receipt.outcome = 'duplicate'
             THEN '$.originalReceipt.enforcedFence' ELSE '$.enforcedFence' END
         ) AS source_enforced_fence,
         json_extract(
           receipt.receipt_json,
           CASE WHEN receipt.outcome = 'duplicate'
             THEN '$.originalReceipt.effectRef' ELSE '$.effectRef' END
         ) AS source_effect_ref_commitment
       FROM runtime_run_commands command
       JOIN runtime_run_command_dispatch dispatch ON dispatch.command_id = command.id
       JOIN runtime_assignments assignment ON assignment.id = command.runtime_assignment_id
       JOIN runtime_run_command_receipts receipt ON receipt.id = (
         SELECT candidate.id
         FROM runtime_run_command_receipts candidate
         WHERE candidate.command_id = command.id
           AND (
             candidate.outcome = 'enforced' OR
             (candidate.outcome = 'duplicate' AND candidate.original_outcome = 'enforced')
           )
         ORDER BY candidate.version ASC, candidate.id ASC
         LIMIT 1
       )
       WHERE dispatch.status = 'compensating'
         AND NOT EXISTS (
           SELECT 1 FROM runtime_run_command_effects effect
           WHERE effect.command_id = command.id
         )
       ORDER BY
         assignment.team_id, assignment.project_id, command.session_id,
         command.runtime_assignment_id, command.runtime_assignment_generation,
         command.sandbox_id, command.sandbox_generation, command.runtime_principal_id,
         receipt.received_at_ms, command.id`
    )
    .all() as Array<Record<string, unknown>>;

  const insert = db.prepare(`
    INSERT INTO runtime_compensation_incidents (
      compensation_id, incident_digest, source_command_id, source_receipt_id, trust_state,
      session_id, team_id, project_id, agent_run_id, run_policy_revision,
      runtime_assignment_id, runtime_assignment_generation,
      sandbox_id, sandbox_generation, runtime_principal_id,
      runtime_authorization_generation, source_command_digest,
      lifecycle_command_claims_digest, lifecycle_receipt_digest,
      source_enforced_fence, safety_fence,
      source_effect_ref_commitment, source_required_effect_enforcer_set_digest,
      lifecycle_enforcement_subject_digest, lifecycle_aggregate_proof_digest,
      source_proof_verified_at_ms, created_at_ms
    ) VALUES (
      @compensation_id, @incident_digest, @source_command_id, @source_receipt_id, @trust_state,
      @session_id, @team_id, @project_id, @agent_run_id, @run_policy_revision,
      @runtime_assignment_id, @runtime_assignment_generation,
      @sandbox_id, @sandbox_generation, @runtime_principal_id,
      @runtime_authorization_generation, @source_command_digest,
      @lifecycle_command_claims_digest, @lifecycle_receipt_digest,
      @source_enforced_fence, @safety_fence,
      @source_effect_ref_commitment, @source_required_effect_enforcer_set_digest,
      @lifecycle_enforcement_subject_digest, @lifecycle_aggregate_proof_digest,
      @source_proof_verified_at_ms, @created_at_ms
    )
  `);

  const allocateSafetyFence = db.prepare(`
    UPDATE runtime_binding_safety_fences
    SET allocated_fence = allocated_fence + 1,
        updated_at_ms = MAX(updated_at_ms, @updated_at_ms)
    WHERE team_id = @team_id
      AND project_id = @project_id
      AND session_id = @session_id
      AND runtime_assignment_id = @runtime_assignment_id
      AND runtime_assignment_generation = @runtime_assignment_generation
      AND sandbox_id = @sandbox_id
      AND sandbox_generation = @sandbox_generation
      AND runtime_principal_id = @runtime_principal_id
      AND allocated_fence < 9007199254740991
    RETURNING allocated_fence
  `);
  for (const candidate of candidates) {
    const proofVerifiedAtMs = candidate.source_proof_verified_at_ms;
    const receivedAtMs = candidate.received_at_ms;
    const sourceRequiredDigest = candidate.source_required_digest;
    const receiptRequiredDigest = candidate.receipt_required_digest;
    const effectRefCommitment = candidate.source_effect_ref_commitment;
    const sourceEnforcedFence = candidate.source_enforced_fence;
    if (
      typeof sourceEnforcedFence !== "number" ||
      !Number.isSafeInteger(sourceEnforcedFence) ||
      sourceEnforcedFence < 1
    ) {
      throw new Error("Team Session v7 migration found invalid source enforcement evidence");
    }
    const allocation = allocateSafetyFence.get({
      ...candidate,
      updated_at_ms: receivedAtMs,
    }) as { allocated_fence: number } | undefined;
    if (!allocation || allocation.allocated_fence <= sourceEnforcedFence) {
      throw new Error("Team Session v7 migration could not allocate a safe compensation fence");
    }
    const safetyFence = allocation.allocated_fence;
    const verified =
      isSha256(sourceRequiredDigest) &&
      receiptRequiredDigest === sourceRequiredDigest &&
      isSha256(candidate.lifecycle_enforcement_subject_digest) &&
      isSha256(candidate.lifecycle_aggregate_proof_digest) &&
      typeof proofVerifiedAtMs === "number" &&
      typeof receivedAtMs === "number" &&
      proofVerifiedAtMs >= 0 &&
      proofVerifiedAtMs <= receivedAtMs &&
      isRuntimeEffectRefCommitment(effectRefCommitment);
    const compensationId = `migration-v7:${createHash("sha256")
      .update("terminalx/runtime-compensation-migration-id/v1\0", "utf8")
      .update(String(candidate.source_command_id), "utf8")
      .update("\0", "utf8")
      .update(String(candidate.source_receipt_id), "utf8")
      .digest("hex")}`;
    const incidentSnapshot = {
      version: 1,
      compensationId,
      sourceCommandId: candidate.source_command_id,
      sourceReceiptId: candidate.source_receipt_id,
      trustState: verified ? "verified" : "legacy-untrusted",
      binding: {
        teamId: candidate.team_id,
        projectId: candidate.project_id,
        sessionId: candidate.session_id,
        runtimeAssignmentId: candidate.runtime_assignment_id,
        runtimeAssignmentGeneration: candidate.runtime_assignment_generation,
        sandboxId: candidate.sandbox_id,
        sandboxGeneration: candidate.sandbox_generation,
        runtimePrincipalId: candidate.runtime_principal_id,
      },
      observedRuntimeAuthorizationGeneration: candidate.runtime_authorization_generation,
      lifecycleCommandClaimsDigest: candidate.lifecycle_command_claims_digest,
      lifecycleReceiptDigest: candidate.lifecycle_receipt_digest,
      sourceEnforcedFence,
      safetyFence,
      sourceRequiredEffectEnforcerSetDigest: verified ? sourceRequiredDigest : null,
      lifecycleEnforcementSubjectDigest: verified
        ? candidate.lifecycle_enforcement_subject_digest
        : null,
      lifecycleAggregateProofDigest: verified ? candidate.lifecycle_aggregate_proof_digest : null,
      sourceEffectRefCommitment: verified ? effectRefCommitment : null,
      createdAtMs: receivedAtMs,
    };
    const incidentDigest = digestRuntimeCompensationIncident(incidentSnapshot);
    insert.run({
      ...candidate,
      compensation_id: compensationId,
      incident_digest: incidentDigest,
      trust_state: verified ? "verified" : "legacy-untrusted",
      source_effect_ref_commitment: verified ? effectRefCommitment : null,
      source_required_effect_enforcer_set_digest: verified ? sourceRequiredDigest : null,
      lifecycle_enforcement_subject_digest: verified
        ? candidate.lifecycle_enforcement_subject_digest
        : null,
      lifecycle_aggregate_proof_digest: verified
        ? candidate.lifecycle_aggregate_proof_digest
        : null,
      source_proof_verified_at_ms: verified ? proofVerifiedAtMs : null,
      safety_fence: safetyFence,
      created_at_ms: receivedAtMs,
    });
  }

  const uncovered = db
    .prepare(
      `SELECT dispatch.command_id
       FROM runtime_run_command_dispatch dispatch
       LEFT JOIN runtime_compensation_incidents incident
         ON incident.source_command_id = dispatch.command_id
       WHERE dispatch.status = 'compensating'
         AND incident.source_command_id IS NULL
       LIMIT 1`
    )
    .get();
  if (uncovered) {
    throw new Error("Team Session v7 migration found a compensating dispatch without evidence");
  }
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function isRuntimeEffectRefCommitment(value: unknown): value is string {
  return typeof value === "string" && /^effect:v1:[0-9a-f]{64}$/.test(value);
}

function parkLegacyRuntimeDispatchesForV6Migration(db: Database.Database): void {
  // Schema v5 had no durable pre-dispatch marker, so a processing lease cannot
  // prove whether Runtime observed the command. Preserve that uncertainty
  // across upgrade instead of letting v6 reconcile it as safely retryable.
  db.prepare(
    `UPDATE runtime_run_command_dispatch
     SET status = 'awaiting-receipt',
         available_at_ms = MAX(available_at_ms, updated_at_ms),
         lease_owner = NULL, lease_expires_at_ms = NULL,
         dispatch_interlock_acquired_at_ms = NULL,
         last_safe_error_code = 'migration_dispatch_uncertain'
     WHERE status = 'processing'`
  ).run();
}

function addRuntimeReceiptFollowV6Columns(db: Database.Database): void {
  addColumnIfMissing(
    db,
    "runtime_run_command_dispatch",
    "dispatch_interlock_acquired_at_ms",
    `ALTER TABLE runtime_run_command_dispatch
       ADD COLUMN dispatch_interlock_acquired_at_ms INTEGER CHECK (
         dispatch_interlock_acquired_at_ms IS NULL OR
         dispatch_interlock_acquired_at_ms >= created_at_ms
       )`
  );
  addColumnIfMissing(
    db,
    "runtime_authorization_epochs",
    "effect_enforcer_set_digest",
    `ALTER TABLE runtime_authorization_epochs
       ADD COLUMN effect_enforcer_set_digest TEXT CHECK (
         effect_enforcer_set_digest IS NULL OR (
           length(effect_enforcer_set_digest) = 64 AND
           effect_enforcer_set_digest = lower(effect_enforcer_set_digest) AND
           effect_enforcer_set_digest NOT GLOB '*[^0-9a-f]*'
         )
       )`
  );
  for (const [table, column] of [
    ["run_policy_revisions", "required_effect_enforcer_set_digest"],
    ["runtime_run_commands", "required_effect_enforcer_set_digest"],
    ["runtime_run_command_receipts", "required_effect_enforcer_set_digest"],
    ["runtime_run_command_receipts", "enforcement_subject_digest"],
    ["runtime_run_command_receipts", "aggregate_proof_digest"],
  ] as const) {
    addColumnIfMissing(
      db,
      table,
      column,
      `ALTER TABLE ${table} ADD COLUMN ${column} TEXT CHECK (
         ${column} IS NULL OR (
           length(${column}) = 64 AND ${column} = lower(${column}) AND
           ${column} NOT GLOB '*[^0-9a-f]*'
         )
       )`
    );
  }
  addColumnIfMissing(
    db,
    "runtime_run_command_receipts",
    "proof_verified_at_ms",
    `ALTER TABLE runtime_run_command_receipts
       ADD COLUMN proof_verified_at_ms INTEGER CHECK (
         proof_verified_at_ms IS NULL OR proof_verified_at_ms >= 0
       )`
  );
}

function addColumnIfMissing(
  db: Database.Database,
  table: string,
  column: string,
  statement: string
): void {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (!columns.some((entry) => entry.name === column)) db.exec(statement);
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
    if (fs.existsSync(/* turbopackIgnore: true */ candidate)) {
      fs.chmodSync(/* turbopackIgnore: true */ candidate, 0o600);
    }
  }
}
