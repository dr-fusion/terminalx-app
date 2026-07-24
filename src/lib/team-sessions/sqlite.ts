import * as fs from "fs";
import * as path from "path";
import Database from "better-sqlite3";

const SCHEMA_VERSION = 5;
const PRE_RUNTIME_START_SCHEMA_VERSION = 4;
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
  WHERE status IN ('provisioning', 'ready', 'checkpointing', 'recovering', 'quarantined');

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
        migratedVersion !== SCHEMA_VERSION
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
      if (currentVersion === SCHEMA_VERSION) return;
      if (currentVersion !== PRE_RUNTIME_START_SCHEMA_VERSION) {
        throw new Error(
          `Unsupported Team Session database schema ${currentVersion}; expected ${SCHEMA_VERSION}`
        );
      }

      db.exec(RUNTIME_START_SCHEMA_V5);
      const violations = db.pragma("foreign_key_check") as unknown[];
      if (violations.length > 0) {
        throw new Error("Team Session v5 migration failed its foreign key check");
      }
      db.pragma(`user_version = ${SCHEMA_VERSION}`);
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
