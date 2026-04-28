import { createServer, IncomingMessage } from "http";
import { parse as parseUrl } from "url";
import next from "next";
import { WebSocketServer, WebSocket } from "ws";
import { watch, FSWatcher } from "chokidar";
import * as path from "path";
import * as fs from "fs";
import type { Socket } from "net";
import { audit } from "../src/lib/audit-log";
import { canAccessSession } from "../src/lib/session-scope";
import type { JwtPayload } from "../src/lib/auth";

interface AuthenticatedRequest extends IncomingMessage {
  user?: JwtPayload;
}

// Import server-side modules
import {
  createPty,
  resizePty,
  destroyPty,
  setMaxSessions,
  destroyAllPtys,
} from "../src/lib/pty-manager";
import { execFileSync } from "child_process";
import { applyGlobalOptions, tmuxTarget } from "../src/lib/tmux";
import { createLogStream, destroyLogStream, destroyAllLogStreams } from "../src/lib/log-streamer";
import { startRecorder, sweepExpiredRecordings } from "../src/lib/session-recorder";
import { verifyJwt, parseCookies } from "../src/lib/auth";
import { getAuthMode } from "../src/lib/auth-config";
import { ensureDefaultAdmin } from "../src/lib/users";
import { startTelegramBot, stopTelegramBot, handleTelegramUpdate } from "../src/lib/telegram/bot";
import {
  allowsNoAuthOnPublicHost,
  getConfiguredMaxSessions,
  shouldRefuseNoAuth,
} from "../src/lib/security-config";

// ── Config ──────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || "3000", 10);
const TERMINUS_ROOT = path.resolve(process.env.TERMINUS_ROOT || process.env.HOME || "/");
const TERMINUS_SHELL = process.env.TERMINUS_SHELL || process.env.SHELL || "/bin/bash";
const TERMINUS_SCROLLBACK = parseInt(process.env.TERMINUS_SCROLLBACK || "10000", 10);
const TERMINUS_MAX_SESSIONS = getConfiguredMaxSessions();
const TERMINUS_READ_ONLY = process.env.TERMINUS_READ_ONLY === "true";
const TERMINUS_HOST = process.env.TERMINUS_HOST || "127.0.0.1";

setMaxSessions(TERMINUS_MAX_SESSIONS);
// Bump tmux's global history-limit so newly-spawned sessions keep deep
// scrollback. Safe no-op if no tmux server is running yet.
applyGlobalOptions();

const AUTH_MODE = getAuthMode();

if (shouldRefuseNoAuth(AUTH_MODE, TERMINUS_HOST)) {
  console.error(
    "[security] refusing to start with TERMINALX_AUTH_MODE=none on a non-loopback host. " +
      "Set TERMINALX_AUTH_MODE=local/password/google, bind to 127.0.0.1, or set TERMINALX_ALLOW_NO_AUTH=1."
  );
  process.exit(1);
}

if (AUTH_MODE === "none" && allowsNoAuthOnPublicHost()) {
  console.warn("[security] authentication is disabled by TERMINALX_ALLOW_NO_AUTH=1");
}

function warnIfReadableByGroupOrWorld(filePath: string): void {
  if (process.platform === "win32") return;
  try {
    const stat = fs.statSync(filePath);
    if ((stat.mode & 0o077) !== 0) {
      console.warn(`[security] ${filePath} is group/world readable; expected mode 0600`);
    }
  } catch {
    // Missing files are normal on first run.
  }
}

// ── WebSocket Auth Helper ──────────────────────────────────────────────────

async function authenticateWebSocket(req: IncomingMessage, socket: Socket): Promise<boolean> {
  // Only skip auth when explicitly in "none" mode
  if (AUTH_MODE === "none") return true;

  const cookies = parseCookies(req.headers.cookie);
  const token = cookies["terminalx-session"];

  if (!token) {
    audit("ws_auth_failed", { detail: "missing cookie" });
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return false;
  }

  const payload = await verifyJwt(token);
  if (!payload) {
    audit("ws_auth_failed", { detail: "invalid token" });
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return false;
  }

  // Attach user info to request
  (req as AuthenticatedRequest).user = payload;
  return true;
}

// ── Next.js App ─────────────────────────────────────────────────────────────

const dev = process.env.NODE_ENV !== "production";
const app = next({ dev, dir: path.resolve(__dirname, "..") });
const handle = app.getRequestHandler();

// ── WebSocket Servers (noServer mode) ───────────────────────────────────────

// maxPayload is a receive-side limit, but the ws library also guards
// sends against truly oversized frames. 4 MB gives comfortable headroom
// for scrollback-chunk payloads after JSON/ANSI-escape expansion.
const terminalWss = new WebSocketServer({ noServer: true, maxPayload: 4 * 1024 * 1024 });
const logsWss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 }); // 64KB
const filesWss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 }); // 64KB

// ── Terminal WebSocket Handler ──────────────────────────────────────────────

terminalWss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
  const url = parseUrl(req.url || "", true);
  const pathParts = (url.pathname || "").split("/");
  // /ws/terminal/:sessionId
  const sessionId = pathParts[3];

  if (!sessionId || !/^[a-zA-Z0-9_.\-]+$/.test(sessionId)) {
    ws.close(1008, "Invalid session ID");
    return;
  }

  // Per-user scoping: non-admin users can only access their own sessions
  const user = (req as AuthenticatedRequest).user;
  if (user && !canAccessSession(user.username, user.role, sessionId)) {
    ws.close(1008, "Access denied");
    return;
  }

  audit("terminal_connected", {
    username: user?.username,
    detail: sessionId,
  });

  if (TERMINUS_READ_ONLY) {
    ws.close(1008, "Read-only mode: terminal access disabled");
    return;
  }

  const cols = parseInt(String(url.query.cols) || "80", 10);
  const rows = parseInt(String(url.query.rows) || "24", 10);

  let ptyInstance;
  try {
    ptyInstance = createPty(sessionId, TERMINUS_SHELL, cols, rows);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    ws.close(1011, message);
    return;
  }

  // Send PTY ID to client
  ws.send(JSON.stringify({ type: "pty-id", id: ptyInstance.id }));

  // (We don't seed xterm's scrollback buffer anymore. tmux attach puts
  // every client on the tmux alt-screen, so anything written to xterm's
  // main buffer is invisible. Scrolling is driven via tmux copy-mode
  // through the {type:"scroll"} control messages below.)

  // Optional session recording
  const recorder = startRecorder({
    sessionId,
    username: user?.username,
    cols,
    rows,
  });
  if (recorder) {
    audit("replay_started", {
      username: user?.username,
      detail: recorder.id,
    });
  }

  // PTY output -> WebSocket
  const dataHandler = ptyInstance.process.onData((data: string) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
    recorder?.write(data);
  });

  // PTY exit (user typed `exit`, tmux session killed, shell died) ->
  // tell the client the session is gone so it can close the tab and
  // refresh the sidebar. Use close code 4000 to signal "not a network
  // blip" — the client suppresses auto-reconnect for that code.
  const exitHandler = ptyInstance.process.onExit(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "session-ended", sessionId }));
      ws.close(4000, "Session ended");
    }
  });

  // WebSocket -> PTY input
  ws.on("message", (msg: Buffer | string) => {
    const data = typeof msg === "string" ? msg : msg.toString("utf-8");

    // Check for control messages (JSON)
    if (data.startsWith("{")) {
      try {
        const parsed = JSON.parse(data);
        if (parsed.type === "resize" && parsed.cols && parsed.rows) {
          resizePty(ptyInstance.id, parsed.cols, parsed.rows);
          return;
        }
        // Scroll control — tmux always runs its client on the alternate
        // screen buffer, so xterm-level scroll can't reach the shell's
        // real history. Drive tmux's own copy-mode from the server:
        // enter copy mode (no-op if already in), run a scroll command,
        // or cancel to return to live output.
        if (parsed.type === "scroll" && typeof parsed.action === "string") {
          const action = parsed.action;
          const scrollCmd: Record<string, string> = {
            up: "page-up",
            down: "page-down",
            "up-line": "scroll-up",
            "down-line": "scroll-down",
            top: "history-top",
            bottom: "history-bottom",
          };
          try {
            const target = tmuxTarget(sessionId);
            if (action === "resume" || action === "cancel") {
              // Kick out of copy mode back to live output. Safe to run
              // even if not currently in copy mode (tmux ignores it).
              execFileSync("tmux", ["send-keys", "-t", target, "-X", "cancel"], {
                timeout: 2000,
              });
            } else if (scrollCmd[action]) {
              // Make sure we're in copy mode before sending a scroll key.
              execFileSync("tmux", ["copy-mode", "-t", target], { timeout: 2000 });
              execFileSync("tmux", ["send-keys", "-t", target, "-X", scrollCmd[action]], {
                timeout: 2000,
              });
            }
          } catch (err) {
            console.error("[scroll] tmux command failed", err);
          }
          return;
        }
      } catch {
        // Not JSON, treat as terminal input
      }
    }

    ptyInstance.process.write(data);
  });

  ws.on("close", () => {
    dataHandler.dispose();
    exitHandler.dispose();
    destroyPty(ptyInstance.id);
    recorder?.close();
    audit("terminal_disconnected", {
      username: user?.username,
      detail: sessionId,
    });
  });

  ws.on("error", () => {
    dataHandler.dispose();
    exitHandler.dispose();
    destroyPty(ptyInstance.id);
    recorder?.close();
  });
});

// ── Log Tailing WebSocket Handler ───────────────────────────────────────────

logsWss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
  const url = parseUrl(req.url || "", true);
  const pathParts = (url.pathname || "").split("/");
  // /ws/logs/:encodedPath
  const encodedPath = pathParts[3];

  // In local multi-user mode, only admins can tail logs (shared host logs
  // may contain other users' traces / secrets).
  const user = (req as AuthenticatedRequest).user;
  if (process.env.TERMINALX_AUTH_MODE === "local" && user && user.role !== "admin") {
    audit("log_access_denied", {
      username: user.username,
      detail: encodedPath,
    });
    ws.close(1008, "Access denied");
    return;
  }

  if (!encodedPath) {
    ws.close(1008, "Missing log file path");
    return;
  }

  let filePath: string;
  try {
    filePath = decodeURIComponent(encodedPath);
  } catch {
    ws.close(1008, "Invalid encoded path");
    return;
  }

  let logStream;
  try {
    logStream = createLogStream(filePath);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    ws.close(1011, message);
    return;
  }

  ws.send(JSON.stringify({ type: "stream-id", id: logStream.id }));

  logStream.emitter.on("data", (data: string) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  });

  logStream.emitter.on("error", (errMsg: string) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "error", message: errMsg }));
    }
  });

  logStream.emitter.on("close", () => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.close(1000, "Log stream ended");
    }
  });

  ws.on("close", () => {
    destroyLogStream(logStream.id);
  });

  ws.on("error", () => {
    destroyLogStream(logStream.id);
  });
});

// ── File Watcher (singleton — shared across all WebSocket clients) ──────────

const fileWatcherClients = new Set<WebSocket>();
let sharedWatcher: FSWatcher | null = null;

function ensureFileWatcher(): void {
  if (sharedWatcher) return;

  sharedWatcher = watch(TERMINUS_ROOT, {
    ignored: [
      /(^|[\/\\])\../, // dotfiles
      "**/node_modules/**",
      "**/.git/**",
      "**/.next/**",
      "**/dist/**",
      "**/build/**",
      "**/.ssh/**",
      "**/.gnupg/**",
      "**/.config/secrets/**",
    ],
    persistent: true,
    ignoreInitial: true,
    depth: 5,
    awaitWriteFinish: {
      stabilityThreshold: 300,
      pollInterval: 100,
    },
  });

  const broadcast = (event: string, filePath: string) => {
    const relativePath = path.relative(TERMINUS_ROOT, filePath);
    const msg = JSON.stringify({
      type: "file-event",
      event,
      path: relativePath,
      timestamp: Date.now(),
    });
    for (const client of fileWatcherClients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(msg);
      }
    }
  };

  sharedWatcher.on("add", (p: string) => broadcast("add", p));
  sharedWatcher.on("change", (p: string) => broadcast("change", p));
  sharedWatcher.on("unlink", (p: string) => broadcast("unlink", p));
  sharedWatcher.on("addDir", (p: string) => broadcast("addDir", p));
  sharedWatcher.on("unlinkDir", (p: string) => broadcast("unlinkDir", p));
}

filesWss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
  const user = (req as AuthenticatedRequest).user;
  if (AUTH_MODE === "local" && (!user || user.role !== "admin")) {
    audit("file_access_denied", {
      username: user?.username,
      detail: "admin required",
    });
    ws.close(1008, "Access denied");
    return;
  }

  ensureFileWatcher();
  fileWatcherClients.add(ws);

  ws.on("close", () => {
    fileWatcherClients.delete(ws);
    // Close shared watcher when no clients remain
    if (fileWatcherClients.size === 0 && sharedWatcher) {
      sharedWatcher.close();
      sharedWatcher = null;
    }
  });

  ws.on("error", () => {
    fileWatcherClients.delete(ws);
  });
});

// ── Start Server ────────────────────────────────────────────────────────────

app.prepare().then(() => {
  const server = createServer((req, res) => {
    const parsedUrl = parseUrl(req.url || "", true);

    // Health endpoint — minimal public info only
    if (parsedUrl.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
      return;
    }

    // Telegram webhook is handled here, in the same module instance that
    // owns the grammy `Bot`. If we let it fall through to Next.js, the
    // route handler runs in a separately-bundled module where the bot
    // reference is null and updates are silently dropped.
    if (parsedUrl.pathname === "/api/telegram/webhook" && req.method === "POST") {
      const expected = process.env.TERMINALX_TELEGRAM_WEBHOOK_SECRET;
      const got = req.headers["x-telegram-bot-api-secret-token"];
      if (!expected || got !== expected) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        try {
          const update = JSON.parse(body) as object;
          // Process async — ack within Telegram's 2 s window. Log only
          // err.message so we don't recursively stringify grammy's
          // BotError, which contains a `ctx.bot` ref that exposes the token.
          void handleTelegramUpdate(update).catch((err: unknown) => {
            const msg = err instanceof Error ? err.message : String(err);
            console.error("[telegram/webhook] handleUpdate failed:", msg);
          });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true }));
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "invalid json" }));
        }
      });
      return;
    }

    // Let Next.js handle everything else
    handle(req, res, parsedUrl);
  });

  // Handle WebSocket upgrade
  server.on("upgrade", async (req: IncomingMessage, socket: Socket, head) => {
    const parsedUrl = parseUrl(req.url || "", true);
    const pathname = parsedUrl.pathname || "";

    // Only authenticate our WebSocket paths (not Next.js HMR)
    const isOurWs =
      pathname.startsWith("/ws/terminal/") ||
      pathname.startsWith("/ws/logs/") ||
      pathname === "/ws/files";

    if (isOurWs) {
      // Validate Origin header to prevent Cross-Site WebSocket Hijacking (CSWSH).
      // Browsers send cookies on cross-origin WS requests, so without this check
      // a malicious page could connect to the terminal using the victim's session.
      const origin = req.headers.origin;
      if (origin) {
        try {
          const originHost = new URL(origin).host;
          const serverHost = req.headers.host;
          if (serverHost && originHost !== serverHost) {
            audit("ws_origin_rejected", { detail: `origin=${origin} host=${serverHost}` });
            socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
            socket.destroy();
            return;
          }
        } catch {
          audit("ws_origin_rejected", { detail: `malformed origin=${origin}` });
          socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
          socket.destroy();
          return;
        }
      }

      const authed = await authenticateWebSocket(req, socket);
      if (!authed) return;
    }

    if (pathname.startsWith("/ws/terminal/")) {
      terminalWss.handleUpgrade(req, socket, head, (ws) => {
        terminalWss.emit("connection", ws, req);
      });
    } else if (pathname.startsWith("/ws/logs/")) {
      logsWss.handleUpgrade(req, socket, head, (ws) => {
        logsWss.emit("connection", ws, req);
      });
    } else if (pathname === "/ws/files") {
      filesWss.handleUpgrade(req, socket, head, (ws) => {
        filesWss.emit("connection", ws, req);
      });
    } else {
      // Pass through to Next.js (needed for HMR WebSocket in dev mode)
      if (dev) {
        // Let Next.js handle its own WebSocket upgrades
        return;
      }
      socket.destroy();
    }
  });

  // Ensure default admin user in local mode
  ensureDefaultAdmin().catch((err) => {
    console.error("[auth] Failed to create default admin:", err);
  });

  const sweep = sweepExpiredRecordings();
  if (sweep.deleted > 0) {
    console.log(`[recorder] swept ${sweep.deleted} expired recording(s)`);
  }

  warnIfReadableByGroupOrWorld(path.resolve(process.cwd(), ".env"));
  warnIfReadableByGroupOrWorld(path.resolve(process.cwd(), "data", "users.json"));
  warnIfReadableByGroupOrWorld(path.resolve(process.cwd(), "data", ".revoked-tokens.json"));
  warnIfReadableByGroupOrWorld(path.resolve(process.cwd(), "data", "telegram-state.json"));

  // Start the Telegram bot if env is configured. Safe no-op when not.
  startTelegramBot().catch((err) => {
    console.error("[telegram] startTelegramBot failed", err);
  });

  server.listen(PORT, TERMINUS_HOST, () => {
    console.log(`TerminalX server ready on http://${TERMINUS_HOST}:${PORT}`);
    console.log(`  Host:       ${TERMINUS_HOST}`);
    console.log(`  Root:       ${TERMINUS_ROOT}`);
    console.log(`  Shell:      ${TERMINUS_SHELL}`);
    console.log(`  Scrollback: ${TERMINUS_SCROLLBACK}`);
    console.log(`  Max PTYs:   ${TERMINUS_MAX_SESSIONS}`);
    console.log(`  Read-only:  ${TERMINUS_READ_ONLY}`);
    console.log(`  Auth:       ${AUTH_MODE}`);
    console.log(`  Mode:       ${dev ? "development" : "production"}`);
  });

  // Graceful shutdown
  const shutdown = () => {
    console.log("\nShutting down...");
    void stopTelegramBot();
    destroyAllPtys();
    destroyAllLogStreams();
    if (sharedWatcher) {
      sharedWatcher.close();
      sharedWatcher = null;
    }
    terminalWss.close();
    logsWss.close();
    filesWss.close();
    server.close(() => {
      process.exit(0);
    });
    // Force exit after 5s
    setTimeout(() => process.exit(1), 5000);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
});
