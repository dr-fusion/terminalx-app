"use client";

import dynamic from "next/dynamic";

const WorkspaceView = dynamic(
  () => import("@/components/workspace/WorkspaceView").then((m) => m.WorkspaceView),
  { ssr: false }
);

export default function WorkspaceIndexPage() {
  return <WorkspaceView activeSession={null} />;
}
