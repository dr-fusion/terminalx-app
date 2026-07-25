import { TEAM_SESSION_SCHEMA_VERSION } from "../team-sessions/types";
import { getRegisteredTeamSessions } from "../team-sessions/service";
import { withConnectionDatabase } from "../identity-service";
import type { InboundDispatchResult, InboundKernelCommand } from "./ingest";

/**
 * Production adapter from the connection ingest pipeline's kernel command to the
 * registered Team Session kernel. The idempotency scope/key derived from the
 * provider replay id makes a redelivery converge on the original event
 * (`replayed: true`) instead of appending a second one.
 */
export async function dispatchInboundKernelCommand(
  command: InboundKernelCommand
): Promise<InboundDispatchResult> {
  const kernel = getRegisteredTeamSessions();
  if (kernel === null) throw new Error("Team Session kernel is unavailable");
  const displayName = withConnectionDatabase((db) => {
    const row = db
      .prepare("SELECT display_name FROM users WHERE id = ? AND status = 'active'")
      .get(command.actorUserId) as { display_name: string } | undefined;
    return row?.display_name ?? command.actorUserId;
  });
  const base = {
    schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
    actor: { kind: "human" as const, userId: command.actorUserId, displayName },
    idempotency: { scope: command.idempotencyScope, key: command.idempotencyKey },
  };
  const result = await kernel.dispatch(
    command.type === "directive.enqueue"
      ? {
          ...base,
          type: "directive.enqueue",
          sessionId: command.sessionId,
          body: command.body,
          expectedSteeringRevision: command.expectedSteeringRevision,
        }
      : {
          ...base,
          type: "comment.add",
          sessionId: command.sessionId,
          body: command.body,
        }
  );
  return { accepted: true, replayed: result.replayed };
}
