"use client";

import { useCallback, useEffect, useLayoutEffect, useRef } from "react";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import {
  AlertCircle,
  CircleStop,
  Eye,
  LoaderCircle,
  RefreshCw,
  ShieldAlert,
  SquareTerminal,
  X,
} from "lucide-react";
import { Terminal } from "xterm";
import "xterm/css/xterm.css";

import { Button } from "@/components/ui/button";
import { useTeamSessionTerminal } from "@/hooks/team-sessions/use-team-session-terminal";
import { cn } from "@/lib/utils";

export interface TeamSessionTerminalProps {
  sessionId: string;
  canObserve: boolean;
  canMutate: boolean;
  sessionStatus: string;
  transportEnabled?: boolean | null;
  className?: string;
}

const MAX_PENDING_OUTPUT_CHARACTERS = 256 * 1024;

export function TeamSessionTerminal({
  sessionId,
  canObserve,
  canMutate,
  sessionStatus,
  transportEnabled,
  className,
}: TeamSessionTerminalProps) {
  const terminalHostRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const pendingOutputRef = useRef("");
  const sendInputRef = useRef<(data: string) => boolean>(() => false);
  const sendResizeRef = useRef<(cols: number, rows: number) => boolean>(() => false);
  const canInputRef = useRef(false);

  const sessionEnded = sessionStatus === "ended";
  const transportReady = transportEnabled !== false && transportEnabled !== null;
  const connectionEnabled = canObserve && !sessionEnded && transportReady;
  const mutationAllowed = canMutate && sessionStatus === "active";

  const handleOutput = useCallback((data: string) => {
    const terminal = terminalRef.current;
    if (terminal) {
      terminal.write(data);
      return;
    }

    const pending = pendingOutputRef.current + data;
    pendingOutputRef.current = pending.slice(-MAX_PENDING_OUTPUT_CHARACTERS);
  }, []);

  const {
    status,
    canInput,
    error,
    hasOutputGap,
    reconnectAttempt,
    retry,
    clearOutputGap,
    sendInput,
    sendResize,
    sendInterrupt,
  } = useTeamSessionTerminal({
    sessionId,
    enabled: connectionEnabled,
    allowMutations: mutationAllowed,
    onOutput: handleOutput,
  });
  const terminalEndedFromConnection = status === "ended";

  useLayoutEffect(() => {
    sendInputRef.current = sendInput;
  }, [sendInput]);
  useLayoutEffect(() => {
    sendResizeRef.current = sendResize;
  }, [sendResize]);
  useLayoutEffect(() => {
    canInputRef.current = canInput;
  }, [canInput]);

  useEffect(() => {
    const host = terminalHostRef.current;
    if (!host || !connectionEnabled || terminalEndedFromConnection) return;

    const styles = getComputedStyle(document.documentElement);
    const terminal = new Terminal({
      allowProposedApi: false,
      cursorBlink: false,
      cursorStyle: "block",
      disableStdin: true,
      fontFamily: "var(--font-jetbrains-mono), 'JetBrains Mono', monospace",
      fontSize: 14,
      lineHeight: 1.4,
      scrollback: 10_000,
      theme: {
        background: cssToken(styles, "--bg-sunken"),
        foreground: cssToken(styles, "--fg-1"),
        cursor: cssToken(styles, "--phosphor"),
        cursorAccent: cssToken(styles, "--fg-inverse"),
        selectionBackground: cssToken(styles, "--phosphor-ghost"),
        selectionForeground: cssToken(styles, "--phosphor-bright"),
        black: cssToken(styles, "--ansi-black"),
        red: cssToken(styles, "--ansi-red"),
        green: cssToken(styles, "--ansi-green"),
        yellow: cssToken(styles, "--ansi-yellow"),
        blue: cssToken(styles, "--ansi-blue"),
        magenta: cssToken(styles, "--ansi-magenta"),
        cyan: cssToken(styles, "--ansi-cyan"),
        white: cssToken(styles, "--ansi-white"),
        brightBlack: cssToken(styles, "--ansi-br-black"),
        brightRed: cssToken(styles, "--ansi-br-red"),
        brightGreen: cssToken(styles, "--ansi-br-green"),
        brightYellow: cssToken(styles, "--ansi-br-yellow"),
        brightBlue: cssToken(styles, "--ansi-br-blue"),
        brightMagenta: cssToken(styles, "--ansi-br-magenta"),
        brightCyan: cssToken(styles, "--ansi-br-cyan"),
        brightWhite: cssToken(styles, "--ansi-br-white"),
      },
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.loadAddon(new WebLinksAddon());
    terminal.open(host);
    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;

    terminal.attachCustomKeyEventHandler((event) => {
      if (!canInputRef.current) return false;
      if (event.type !== "keydown") return true;
      const modifier = event.metaKey || event.ctrlKey;
      return !(modifier && event.key.toLowerCase() === "k");
    });

    const inputSubscription = terminal.onData((data) => {
      sendInputRef.current(data);
    });

    let resizeFrame: number | null = null;
    let lastDimensions = "";
    const fitAndReportDimensions = (): void => {
      if (resizeFrame !== null) return;
      resizeFrame = requestAnimationFrame(() => {
        resizeFrame = null;
        if (terminalRef.current !== terminal) return;
        try {
          fitAddon.fit();
          const dimensions = `${terminal.cols}x${terminal.rows}`;
          if (dimensions !== lastDimensions) {
            lastDimensions = dimensions;
            sendResizeRef.current(terminal.cols, terminal.rows);
          }
        } catch {
          // A hidden tab can briefly have no measurable terminal surface.
        }
      });
    };

    const resizeObserver = new ResizeObserver(fitAndReportDimensions);
    resizeObserver.observe(host);
    fitAndReportDimensions();

    if (pendingOutputRef.current) {
      terminal.write(pendingOutputRef.current);
      pendingOutputRef.current = "";
    }

    return () => {
      resizeObserver.disconnect();
      if (resizeFrame !== null) cancelAnimationFrame(resizeFrame);
      inputSubscription.dispose();
      terminal.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
      pendingOutputRef.current = "";
    };
  }, [connectionEnabled, sessionId, terminalEndedFromConnection]);

  useEffect(() => {
    const terminal = terminalRef.current;
    if (!terminal) return;
    terminal.options.disableStdin = !canInput;
    terminal.options.cursorBlink = canInput;

    if (status !== "ready") return;
    try {
      fitAddonRef.current?.fit();
      sendResize(terminal.cols, terminal.rows);
    } catch {
      // The next ResizeObserver notification will retry once visible.
    }
  }, [canInput, sendResize, status]);

  if (sessionEnded || terminalEndedFromConnection) {
    return (
      <TerminalEmptyState
        className={className}
        icon={CircleStop}
        title="Terminal session ended"
        description="The terminal is closed. The conversation remains available for postmortem comments."
      />
    );
  }

  if (transportEnabled === false) {
    return (
      <TerminalEmptyState
        className={className}
        icon={ShieldAlert}
        title="Multiplayer terminal is disabled"
        description="Set TERMINALX_MULTIPLAYER_ENABLED=true and restart the custom TerminalX server."
      />
    );
  }

  if (!canObserve) {
    return (
      <TerminalEmptyState
        className={className}
        icon={Eye}
        title="Terminal access is not shared"
        description="Ask a Session manager to add you as a participant or share this Session with you."
      />
    );
  }

  if (transportEnabled === null) {
    return (
      <TerminalEmptyState
        className={className}
        icon={AlertCircle}
        title="Terminal transport is not confirmed"
        description="The server has not reported whether multiplayer WebSockets are enabled. Refresh the Session or check the custom server."
      />
    );
  }

  const connectionLabel = terminalConnectionLabel(status, reconnectAttempt);
  const isConnecting = status === "connecting" || status === "reconnecting";
  const hasBlockingError = status === "error" || status === "policy-blocked";

  return (
    <section
      className={cn(
        "flex min-h-80 flex-1 flex-col overflow-hidden rounded-lg border border-border bg-[var(--bg-sunken)]",
        className
      )}
      aria-label="Shared Session terminal"
      data-testid="team-session-terminal"
    >
      <header className="flex min-h-12 flex-wrap items-center gap-2 border-b border-border bg-card px-3 py-2">
        <div className="flex min-w-0 flex-1 items-center gap-2">
          <SquareTerminal className="size-4 shrink-0 text-primary" aria-hidden="true" />
          <span className="text-sm font-medium text-foreground">Terminal</span>
          <span
            className="inline-flex items-center gap-1.5 text-xs text-[var(--fg-2)]"
            aria-live="polite"
          >
            <span
              className={cn(
                "size-1.5 rounded-full",
                status === "ready"
                  ? "bg-primary"
                  : hasBlockingError
                    ? "bg-destructive"
                    : "bg-[var(--amber)]"
              )}
              aria-hidden="true"
            />
            {connectionLabel}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span
            className={cn(
              "rounded-md border px-2 py-1 text-xs",
              canInput
                ? "border-primary/50 bg-primary/10 text-primary"
                : "border-border bg-muted text-[var(--fg-2)]"
            )}
          >
            {canInput ? "Controller input" : "Observe only"}
          </span>
          <Button
            type="button"
            variant="outline"
            className="h-10"
            disabled={!canInput}
            onClick={() => {
              if (sendInterrupt()) terminalRef.current?.focus();
            }}
            title={
              canInput ? "Send an interrupt to the terminal" : "Only the Controller can interrupt"
            }
          >
            <CircleStop aria-hidden="true" />
            Interrupt
          </Button>
        </div>
      </header>

      <div className="flex items-start gap-2 border-b border-[var(--amber-dim)]/50 bg-[var(--amber-ghost)] px-3 py-2 text-xs text-[var(--amber)]">
        <ShieldAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <p>
          <span className="font-medium">LocalTmux · trusted-host development.</span> Processes run
          on the TerminalX host, not in a Daytona Sandbox.
        </p>
      </div>

      {!canInput && status === "ready" ? (
        <div className="border-b border-border bg-muted/40 px-3 py-2 text-xs text-[var(--fg-2)]">
          You can select and copy output. Only the current Controller can type, resize, or
          interrupt.
        </div>
      ) : null}

      {hasOutputGap ? (
        <div
          className="flex items-center gap-2 border-b border-[var(--amber-dim)]/50 bg-[var(--amber-ghost)] px-3 py-1 text-xs text-[var(--amber)]"
          role="status"
        >
          <AlertCircle className="size-4 shrink-0" aria-hidden="true" />
          <span className="min-w-0 flex-1">
            The connection was interrupted. Output produced while disconnected may be missing.
          </span>
          <Button
            type="button"
            variant="ghost"
            className="size-10 shrink-0 p-0 text-[var(--amber)] hover:bg-[var(--amber)]/10 hover:text-[var(--amber)]"
            onClick={clearOutputGap}
            aria-label="Dismiss output gap notice"
          >
            <X aria-hidden="true" />
          </Button>
        </div>
      ) : null}

      <div className="relative min-h-64 flex-1 bg-[var(--bg-sunken)]">
        <div
          ref={terminalHostRef}
          className="absolute inset-0"
          role="region"
          aria-label="Terminal output"
        />

        {isConnecting ? (
          <div className="absolute inset-0 flex items-center justify-center bg-background/75 p-6 backdrop-blur-sm">
            <div className="flex max-w-sm flex-col items-center gap-3 text-center" role="status">
              <LoaderCircle
                className="size-6 text-primary motion-safe:animate-spin"
                aria-hidden="true"
              />
              <div>
                <p className="text-sm font-medium text-foreground">{connectionLabel}</p>
                <p className="mt-1 text-xs text-[var(--fg-2)]">
                  Waiting for the scoped terminal authorization fences.
                </p>
              </div>
            </div>
          </div>
        ) : null}

        {hasBlockingError ? (
          <div className="absolute inset-0 flex items-center justify-center bg-background/90 p-6">
            <div className="flex max-w-md flex-col items-center gap-3 text-center" role="alert">
              <AlertCircle className="size-6 text-destructive" aria-hidden="true" />
              <div>
                <p className="text-sm font-medium text-foreground">
                  {status === "policy-blocked"
                    ? "Terminal access needs attention"
                    : "Could not connect to the terminal"}
                </p>
                <p className="mt-1 text-xs text-[var(--fg-2)]">
                  {error ?? "Check the Session and try again."}
                </p>
              </div>
              <Button type="button" variant="outline" className="h-10" onClick={retry}>
                <RefreshCw aria-hidden="true" />
                Try again
              </Button>
            </div>
          </div>
        ) : null}
      </div>
    </section>
  );
}

interface TerminalEmptyStateProps {
  className?: string;
  icon: typeof Eye;
  title: string;
  description: string;
}

function TerminalEmptyState({
  className,
  icon: Icon,
  title,
  description,
}: TerminalEmptyStateProps) {
  return (
    <section
      className={cn(
        "flex min-h-80 flex-1 items-center justify-center rounded-lg border border-border bg-[var(--bg-sunken)] p-6",
        className
      )}
      aria-label="Shared Session terminal"
    >
      <div className="flex max-w-md flex-col items-center gap-3 text-center">
        <Icon className="size-8 text-[var(--fg-2)]" aria-hidden="true" />
        <div>
          <p className="text-sm font-medium text-foreground">{title}</p>
          <p className="mt-1 text-xs text-[var(--fg-2)]">{description}</p>
        </div>
      </div>
    </section>
  );
}

function terminalConnectionLabel(status: string, reconnectAttempt: number): string {
  switch (status) {
    case "idle":
      return "Not connected";
    case "connecting":
      return "Connecting…";
    case "ready":
      return "Live";
    case "reconnecting":
      return `Reconnecting${reconnectAttempt > 0 ? ` · attempt ${reconnectAttempt}` : ""}…`;
    case "ended":
      return "Ended";
    case "policy-blocked":
      return "Access changed";
    case "error":
      return "Unavailable";
    default:
      return "Unknown";
  }
}

function cssToken(styles: CSSStyleDeclaration, token: string): string {
  return styles.getPropertyValue(token).trim();
}
