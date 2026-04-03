"use client";

import dynamic from "next/dynamic";

const WorkspaceLayout = dynamic(
  () => import("@/components/layout/WorkspaceLayout"),
  { ssr: false }
);

export default function Home() {
  return <WorkspaceLayout />;
}
