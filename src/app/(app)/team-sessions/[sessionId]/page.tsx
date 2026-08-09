import { TeamSessionsView } from "@/components/team-sessions/TeamSessionsView";

export default async function TeamSessionPage({
  params,
}: {
  params: Promise<{ sessionId: string }>;
}) {
  const { sessionId } = await params;
  return <TeamSessionsView selectedSessionId={sessionId} />;
}
