"use client";

import { useTerminalEngine } from "@/hooks/useTerminalEngine";
import { TerminalViewXterm } from "./TerminalViewXterm";
import { TerminalViewWterm } from "./TerminalViewWterm";
import type { TerminalViewProps } from "./types";

export function TerminalView(props: TerminalViewProps) {
  const { engine } = useTerminalEngine();
  return engine === "wterm" ? (
    <TerminalViewWterm {...props} />
  ) : (
    <TerminalViewXterm {...props} />
  );
}
