"use client";

import { useEffect, useState } from "react";

/** Format an unread count for the nav badge (caps at 99+). Pure; unit-tested. */
export function formatUnreadBadge(count: number): string | null {
  if (!Number.isFinite(count) || count <= 0) return null;
  return count > 99 ? "99+" : String(Math.floor(count));
}

async function fetchUnreadCount(signal: AbortSignal): Promise<number> {
  const response = await fetch("/api/attention/unread-count", {
    headers: { accept: "application/json" },
    signal,
  });
  if (!response.ok) throw new Error(`Unread count failed with ${response.status}`);
  const body = (await response.json()) as { unreadCount: number };
  return typeof body.unreadCount === "number" ? body.unreadCount : 0;
}

export function InboxBadge() {
  const [count, setCount] = useState(0);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const poll = async () => {
      try {
        const value = await fetchUnreadCount(controller.signal);
        if (active) setCount(value);
      } catch {
        // A transient failure leaves the last known count; never surface an error here.
      }
    };
    void poll();
    const timer = setInterval(() => void poll(), 60_000);
    return () => {
      active = false;
      controller.abort();
      clearInterval(timer);
    };
  }, []);

  const label = formatUnreadBadge(count);
  if (label === null) return null;
  return (
    <span
      className="ml-auto inline-flex min-w-5 items-center justify-center rounded-full bg-[#00ff88] px-1.5 text-[10px] font-semibold text-[#002a17]"
      aria-label={`${count} unread`}
    >
      {label}
    </span>
  );
}
