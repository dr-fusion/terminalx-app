"use client";

import { useSyncExternalStore } from "react";

const LEGACY_STORAGE_KEY = "terminalx:open-tabs";
const STORAGE_KEY = "terminalx:open-tabs:v1";
const EMPTY_TABS: string[] = [];

let tabsSnapshot = EMPTY_TABS;
let hydrated = false;
let listening = false;
const subscribers = new Set<() => void>();

function sanitize(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  const tabs: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || !item || seen.has(item)) continue;
    seen.add(item);
    tabs.push(item);
  }
  return tabs;
}

function parse(raw: string | null): string[] {
  if (!raw) return [];
  try {
    return sanitize(JSON.parse(raw));
  } catch {
    return [];
  }
}

function sameTabs(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((tab, index) => tab === right[index]);
}

function persist(tabs: string[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(tabs));
  } catch {
    // localStorage can be unavailable or full; the in-memory store still works.
  }
}

function readStoredTabs(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const versioned = window.localStorage.getItem(STORAGE_KEY);
    if (versioned !== null) return parse(versioned);

    const legacy = window.localStorage.getItem(LEGACY_STORAGE_KEY);
    const migrated = parse(legacy);
    if (legacy !== null) {
      // Migrate the former unversioned raw-array schema without notifying
      // subscribers during render/hydration.
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(migrated));
      window.localStorage.removeItem(LEGACY_STORAGE_KEY);
    }
    return migrated;
  } catch {
    return [];
  }
}

function ensureHydrated(): void {
  if (hydrated || typeof window === "undefined") return;
  tabsSnapshot = readStoredTabs();
  hydrated = true;
}

function publish(next: string[], shouldPersist = true): string[] {
  ensureHydrated();
  const sanitized = sanitize(next);
  if (sameTabs(tabsSnapshot, sanitized)) return tabsSnapshot;

  tabsSnapshot = sanitized;
  if (shouldPersist) persist(tabsSnapshot);
  for (const subscriber of subscribers) subscriber();
  return tabsSnapshot;
}

function onStorage(event: StorageEvent): void {
  if (event.key === STORAGE_KEY) {
    publish(parse(event.newValue), false);
    return;
  }

  // A still-open tab running the previous schema may write the legacy key.
  if (event.key === LEGACY_STORAGE_KEY && event.newValue !== null) {
    const next = parse(event.newValue);
    publish(next);
    try {
      window.localStorage.removeItem(LEGACY_STORAGE_KEY);
    } catch {
      // ignore
    }
  }
}

function onSessionEnded(event: Event): void {
  const detail = (event as CustomEvent<{ sessionId?: string }>).detail;
  if (detail?.sessionId) closeTab(detail.sessionId);
}

function attachListeners(): void {
  if (listening || typeof window === "undefined") return;
  window.addEventListener("storage", onStorage);
  window.addEventListener("terminalx:session-ended", onSessionEnded);
  listening = true;
}

function detachListeners(): void {
  if (!listening || typeof window === "undefined") return;
  window.removeEventListener("storage", onStorage);
  window.removeEventListener("terminalx:session-ended", onSessionEnded);
  listening = false;
}

function subscribe(subscriber: () => void): () => void {
  ensureHydrated();
  subscribers.add(subscriber);
  attachListeners();
  return () => {
    subscribers.delete(subscriber);
    if (subscribers.size === 0) {
      detachListeners();
      // Re-read storage if the app shell later remounts; another window may
      // have changed tabs while this page had no subscribers.
      hydrated = false;
    }
  };
}

function getSnapshot(): string[] {
  ensureHydrated();
  return tabsSnapshot;
}

function getServerSnapshot(): string[] {
  return EMPTY_TABS;
}

export function openTab(sessionId: string): string[] {
  ensureHydrated();
  if (!sessionId || tabsSnapshot.includes(sessionId)) return tabsSnapshot;
  return publish([...tabsSnapshot, sessionId]);
}

export function closeTab(sessionId: string): string[] {
  ensureHydrated();
  return publish(tabsSnapshot.filter((tab) => tab !== sessionId));
}

export function reconcileTabs(validSessionIds: Iterable<string>): string[] {
  ensureHydrated();
  const valid = new Set(validSessionIds);
  return publish(tabsSnapshot.filter((tab) => valid.has(tab)));
}

export function useOpenTabs() {
  const tabs = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  return { tabs, openTab, closeTab, reconcileTabs };
}
