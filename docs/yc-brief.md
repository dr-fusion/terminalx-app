# TerminalX Multiplayer — shareable project brief

## One-line description

TerminalX Multiplayer is a collaborative control room for long-running coding agents: teams can
watch the same terminal and conversation, steer work together, hand off responsibility, and keep
autonomous execution inside an isolated, auditable Sandbox.

## The problem

Coding agents are increasingly able to work for minutes or hours, but their collaboration model is
still mostly one person, one chat, and one laptop. That breaks down inside real teams:

- a senior developer can start work and become unavailable when the agent needs a decision;
- a manager or another authorized engineer cannot safely take over without losing context;
- terminal output and chat history are fragmented instead of forming one durable work record;
- broad “skip permissions” modes trade repeated prompts for weak accountability;
- credentials exposed to an agent, shell, log, or model response are difficult to contain;
- local execution cannot provide credible isolation from the developer's machine.

## The product

TerminalX turns an agent session into a shared team object rather than a private chat.

- **Collaborative workspace:** an Orca/Paseo-style session view combines a proper threaded chat,
  live terminal, participant presence, artifacts, and the current Run state.
- **Shared steering:** a controller can authorize multiple steerers. A manager or supervisor can
  take over, assign another steerer, or continue a task when the original operator is unavailable.
- **Durable handoff:** session history, decisions, goals, blockers, approvals, and evidence remain
  available across disconnects and restarts.
- **Members and revocable guests:** teams can invite limited guests and revoke their access without
  weakening the Session's audit or control fences.
- **Long-running autonomy:** supervised, autonomous, and explicitly dangerous YOLO-style runs are
  modeled separately. A Run can continue until all goals are achieved, while high-risk boundaries
  remain explicit and revocable.
- **Sandbox-scoped authority:** approvals and grants are bound to the exact user, policy, Session,
  Runtime Assignment, and Sandbox generation. Changing the Sandbox can invalidate prior authority.
- **Brokered connections:** the production design supports revocable Slack and Telegram identities
  plus secret-manager-backed credentials without making raw tokens or private keys visible to the
  agent, terminal, logs, artifacts, or model output.

## A representative workflow

1. A senior developer starts a task and adds a manager as supervisor.
2. The agent works autonomously in a hosted Sandbox while the team follows the terminal and chat.
3. A deployment, destructive command, secret-dependent operation, or policy exception needs
   attention.
4. If the senior developer is away, the manager can steer directly or assign a junior developer as
   another authorized steerer.
5. The task continues with the same goals and evidence. Every control transfer and material effect
   is version-fenced and recorded.
6. The team can revoke a guest, connection, approval, or whole Sandbox authority without relying on
   the original operator to return.

## Why now

Agent capability is improving faster than the operational layer around it. Teams need collaboration,
identity, isolation, approvals, secret handling, recovery, and evidence around agent work—not just a
larger chat box. TerminalX focuses on that missing multiplayer and control plane.

## Technical approach

The application is built around two deliberately separate authorities:

- the **Team Session kernel** owns membership, guests, responsibilities, controller/steerer fences,
  messages, goals, policy snapshots, approvals, and the canonical read model;
- the **Runtime** owns isolated execution and returns exact-bound receipts and events. Requested
  lifecycle changes do not become Session truth until Runtime enforcement is durably proven.

Production execution uses the public Daytona fork at the immutable hardened merge and reviewed
base declared in [`config/daytona-production-source.json`](../config/daytona-production-source.json).
Provider-native IDs and credentials stay behind the Runtime adapter. Local tmux remains a trusted
development adapter and is never represented as a secure Sandbox.

## Security posture

TerminalX treats autonomy as scoped authority, not a blanket bypass.

- Dangerous mode requires a prominent, expiring, one-use confirmation bound to one Session,
  policy, actor, and Sandbox.
- “Approve for this Run” reduces prompt fatigue but cannot grant authority outside that Sandbox.
- Runtime commands are signed and bound to exact state, policy, assignment, authorization, and
  deadline fences.
- Ambiguous provider outcomes are reconciled under the same command identity; they are not blindly
  retried.
- Raw secrets are intended to exist only at approved broker/proxy boundaries, even if a user or
  agent explicitly asks to reveal them.
- Emergency stop, quarantine, grant invalidation, and compensation are independent of the original
  operator.

## Current status — July 2026

TerminalX is an actively hardened pre-production application, not yet an external-pilot release.
The collaborative kernel, durable conversation, multiplayer workspace, Agent Run model, and Runtime
command/receipt foundation are complete. The portable end-to-end Runtime-truth kernel is complete;
its production activation remains closed until the pinned hosted Daytona adapter supplies the
isolation and real-provider evidence assigned to the next phase. Brokered secrets, authoritative
approvals/limits/YOLO, recovery/evidence, production operations, and adversarial release
verification remain gated.

The authoritative plan contains **13 implementation phases, numbered 0 through 12**. Phases 0–6
are complete, Phase 7 is next, and production is enabled only after all eight security gates and
final operational/release evidence are closed. See
[the production roadmap](./production-readiness/roadmap.md).

## What we are looking for

We want design partners with teams already using coding agents for consequential, long-running work.
The highest-value feedback is around collaborative takeover, escalation, approval fatigue, Sandbox
boundaries, secret-dependent workflows, and the evidence security or engineering leaders need before
they permit autonomous agents in production repositories and infrastructure.
