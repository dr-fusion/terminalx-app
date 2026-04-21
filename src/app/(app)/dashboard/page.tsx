"use client";

import dynamic from "next/dynamic";

const DashboardView = dynamic(
  () => import("@/components/dashboard/DashboardView").then((m) => m.DashboardView),
  { ssr: false }
);

export default function DashboardPage() {
  return <DashboardView />;
}
