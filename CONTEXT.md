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
