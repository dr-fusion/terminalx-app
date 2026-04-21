"use client";

import dynamic from "next/dynamic";

const SettingsView = dynamic(
  () => import("@/components/settings/SettingsView").then((m) => m.SettingsView),
  { ssr: false }
);

export default function SettingsPage() {
  return <SettingsView />;
}
