"use client";

type Listener = (text: string) => void;

const listeners = new Set<Listener>();

export function subscribeToTerminalBus(listener: Listener) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function emitToActiveTerminal(text: string) {
  for (const fn of listeners) {
    try {
      fn(text);
    } catch {
      // ignore listener errors
    }
  }
}
