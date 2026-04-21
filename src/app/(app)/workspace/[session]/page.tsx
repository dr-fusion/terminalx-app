"use client";

import { useParams } from "next/navigation";
import dynamic from "next/dynamic";

const WorkspaceView = dynamic(
  () => import("@/components/workspace/WorkspaceView").then((m) => m.WorkspaceView),
  { ssr: false }
);

export default function WorkspaceSessionPage() {
  const params = useParams<{ session: string }>();
  const session = typeof params?.session === "string" ? decodeURIComponent(params.session) : null;
  return <WorkspaceView activeSession={session} />;
}
