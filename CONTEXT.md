# TerminalX Multiplayer

TerminalX Multiplayer is the collaboration and authority context around long-running agent work.
Its language separates human access, external identities, execution authority, and secrets so that
revoking one relationship cannot silently preserve another.

## Collaboration

**User**:
An authenticated human identity in TerminalX, independent of any team or external service.
_Avoid_: Account, principal, operator

**Team Membership**:
The revocable relationship that gives a User a Team Role within one Team.
_Avoid_: User role, seat

**Team Member**:
A User whose Team Membership is Owner, Admin, or Member and is not restricted to invited Sessions.
_Avoid_: Internal user, employee

**Guest**:
A User whose Team Membership grants access only through explicit, revocable Session shares.
_Avoid_: External member, anonymous user

**Team Session**:
The durable shared record of one collaborative body of agent work, including conversation,
participants, responsibilities, goals, Runs, decisions, and evidence.
_Avoid_: Chat, terminal session, sandbox

**Participant**:
A User admitted to one Team Session. Participation alone does not grant steering authority.
_Avoid_: Viewer, collaborator

**Assignee**:
The single Participant currently responsible for carrying the Team Session forward.
_Avoid_: Owner, operator

**Supervisor**:
A Participant authorized to oversee the Team Session, take control, and delegate steering when the
Assignee is unavailable.
_Avoid_: Manager, approver

**Steerer**:
A Participant authorized to send directives or terminal input under the current steering fence.
_Avoid_: Editor, driver

**Controller**:
The single active Steerer whose control epoch admits live terminal input at a given moment.
_Avoid_: Session owner, assignee

**Handoff Briefing**:
The immutable, structured, server-bounded context a Participant records when offering a responsibility
Handoff — a summary, the current state, first-class blockers, next steps, and links to evidence or
Runs. It travels with the Handoff and is shown to the accepting Participant; it is accountable
context, not itself a grant of authority.
_Avoid_: Note, description, comment

## Attention and delivery

**Attention Item**:
One attention or steering ask directed at a single User — a mention, a Handoff offer awaiting their
acceptance, or an assignee-required ask a Supervisor must resolve — projected across every Team
Session that User can currently see. It is a projection over existing durable authority, always
fenced to an active Participant, never a new authoritative record.
_Avoid_: Notification, task, ticket

**Read Cursor**:
The durable, per-User, per-Team-Session high-water mark of the Attention Items a User has read. It
never regresses, and unread counts derive from it. It is a projection, not evidence.
_Avoid_: Seen flag, last-read timestamp

**Delivery Cursor**:
The append-only, per-User, hash-chained record of which Attention Items have been delivered to a
User's bound external channel, and with what outcome. It makes external delivery idempotent across
retry and restart and is evidence of what was delivered, not an authorization to deliver.
_Avoid_: Sent log, outbox

**Attention Escalation**:
The append-only, per-Team-Session, hash-chained record that a responsible Participant did not act on
an Attention Item before its deadline, so oversight was escalated to a Supervisor. It is evidence of
the escalation, not itself a grant of authority.
_Avoid_: Alert, reminder

## Integrity and recovery

**Session Event Chain**:
The append-only hash chain over a Team Session's events. Each event commits to its
attributable content and to its predecessor's hash from a fixed genesis root, so any
tamper, gap, reorder, or deletion is detectable by recomputing the chain.
_Avoid_: Audit log, event log

**Session Event Checkpoint**:
An Ed25519-signed attestation over a Session Event Chain head (session, head sequence,
head hash) that lets an external retainer prove the head without holding the signing
key. It is evidence of the chain's state, not an authorization.
_Avoid_: Snapshot, backup

**Evidence Review History**:
The immutable, append-only record of who reviewed exactly which evidence at which Goal
version, with what disposition. It is attribution evidence, not the evidence itself.
_Avoid_: Review log, audit entry

**Goal Version Lineage**:
The immutable, append-only record binding each Goal version to its predecessor version
and the command that produced it.
_Avoid_: Goal history, changelog

**Platform-Security Action**:
An authenticated, generation-fenced, single-use quarantine, retire, or retry applied to
a Runtime Assignment for platform-security reasons, including before any Run has bound
it. It is recorded in an append-only history.
_Avoid_: Kill switch, admin override

**Session Archive**:
The terminal, immutable, still-integrity-verifiable state of an ended Team Session,
carrying its end and archive times and a retention horizon.
_Avoid_: Deleted session, backup

## Execution

**Run**:
A durable attempt by an agent to pursue a versioned set of Goals under one policy and Runtime
Assignment.
_Avoid_: Job, task, session

**Runtime Assignment**:
The versioned authorization binding between one Team Session and its current isolated execution
environment.
_Avoid_: Machine, container, sandbox ID

**Sandbox**:
The isolated execution environment owned by the Runtime. It is not the Team Session or the Run.
_Avoid_: Session, workspace

**Action Grant**:
An expiring, revocable authorization for a bounded class of effects within one exact Run, policy,
Runtime Assignment, and Sandbox generation.
_Avoid_: Approval, permission bypass

**Approval Provenance**:
The signed, immutable snapshot recorded when an approval is resolved into an Action Grant, binding
the resolving actor, the approved capability, the policy, the budget, the Sandbox identity, and the
grant state at approval time. It is evidence of what was granted, not itself an authorization.
_Avoid_: Audit log entry, approval record

**Reservation**:
A durable, receipt-keyed hold placed on a Run's authoritative limits before an effect, later
settled from the effect's Runtime receipt or released on failure. It is the unit of authoritative
limit accounting, not a prediction or an estimate.
_Avoid_: Quota, budget, estimate

**YOLO Challenge**:
A server-issued, expiring, single-use proof bound to one exact actor, Team Session, run policy, and
Sandbox identity that gates minting the first autonomous ("yolo") Action Grant, consumed atomically
with that grant.
_Avoid_: Confirmation dialog, override, bypass token

## Connections and channels

**Identity Connection**:
A revocable, User-owned link between a TerminalX User and one identity at an external provider. It
establishes attribution; it does not itself grant Team or Team Session access.
_Avoid_: Social login, integration, account

**Channel Installation**:
A Team-owned installation of an external messaging application in one provider tenant, with a
reviewed capability set and lifecycle independent of any User's Identity Connection.
_Avoid_: Bot token, workspace connection

**Link Challenge**:
A single-use, short-lived proof that joins an authenticated TerminalX User to the external identity
that completed the challenge.
_Avoid_: Login code, invite

**Channel Binding**:
A revocable policy relationship that routes one external channel or thread to one TerminalX scope
and defines which inbound and outbound interactions are allowed.
_Avoid_: Webhook, notification setting

## Credentials

**Credential Handle**:
An opaque, non-secret reference to credential material held by an approved Secret Broker. Possessing
the handle never permits reading or exporting the material.
_Avoid_: Secret, token, key

**Secret Broker**:
The trusted authority that resolves Credential Handles only for approved typed operations and never
returns raw credential material to a User, agent, shell, event, log, artifact, or model response.
_Avoid_: Vault, environment variable store

**Credential Proxy**:
The destination-scoped effect boundary that uses a Credential Handle to perform or sign an approved
request without revealing the credential to the caller.
_Avoid_: HTTP proxy, secret injector

**Typed Provider Operation**:
A named, closed entry in the Credential Proxy's operation registry that pins one provider, one
destination host, one method, a bounded parameter schema, and a bounded response projection. It is
the only thing a caller may invoke; there is no generic authenticated-request primitive.
_Avoid_: API call, generic request, endpoint

**Registration Receipt**:
A single-use, Secret Broker-signed proof that binds one exact Credential Handle registration
expectation to a newly prepared handle. The main process verifies it locally to admit the
registration; it is never itself persisted, and TerminalX stores only its digest.
_Avoid_: Token, session, capability

## Operations

**Readiness Probe**:
The dependency-aware health check that reports whether the node can actually serve — SQLite reachable
and migrated to the expected schema, integrity-clean, and the Secret Broker ready when configured. It
fails closed with a bare, non-leaking status so a load balancer holds traffic and no probe discloses
which dependency is degraded. It is distinct from the minimal liveness check.
_Avoid_: Health check, ping, status page

**Pre-migration Snapshot**:
The automatic, fail-closed, transactionally-consistent copy of the database taken by the migration
dispatcher before any schema migration mutates it, using SQLite's `VACUUM INTO` (never a live-WAL
copy). It is the recovery point a migration-aware rollback restores from; if it cannot be written,
the migration is refused.
_Avoid_: Backup, dump, checkpoint

**Restore Drill**:
The verification that a backup is recoverable, not merely present: it backs up the live database,
restores the backup into a throwaway location, and verifies integrity, schema, and the Session Event
Chain over every session. It only reads the live database through the online backup API.
_Avoid_: Backup test, dry run

**Maintenance Tick**:
The periodic server loop that drives existing durable capabilities on a schedule — Attention
escalation and notification delivery, rotated online backups, and recording pruning. It holds no
authority of its own; every step is idempotent and fail-closed.
_Avoid_: Cron job, background task, scheduler
