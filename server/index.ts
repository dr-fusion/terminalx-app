import { createServer, IncomingMessage } from "http";
import { parse as parseUrl } from "url";
import next from "next";
import { WebSocketServer, WebSocket } from "ws";
import { watch } from "chokidar";
import * as path from "path";
import type { Socket } from "net";

// Import server-side modules
import {
  createPty,
  resizePty,
  destroyPty,
  setMaxSessions,
  destroyAllPtys,
  getActivePtyCount,
} from "../src/lib/pty-manager";
import {
  createLogStream,
  destroyLogStream,
  destroyAllLogStreams,
} from "../src/lib/log-streamer";
import { verifyJwt, parseCookies } from "../src/lib/auth";
import { getAuthMode } from "../src/lib/auth-config";
import { ensureDefaultAdmin } from "../src/lib/users";

// ── Config ──────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || "3000", 10);
const TERMINUS_ROOT = path.resolve(
  process.env.TERMINUS_ROOT || process.env.HOME || "/"
);
const TERMINUS_SHELL =
  process.env.TERMINUS_SHELL || process.env.SHELL || "/bin/bash";
const TERMINUS_SCROLLBACK = parseInt(
  process.env.TERMINUS_SCROLLBACK || "10000",
  10
);
const TERMINUS_MAX_SESSIONS = parseInt(
  process.env.TERMINUS_MAX_SESSIONS || "20",
  10
);
const TERMINUS_READ_ONLY = process.env.TERMINUS_READ_ONLY === "true";
const TERMINUS_HOST = process.env.TERMINUS_HOST || "0.0.0.0";

setMaxSessions(TERMINUS_MAX_SESSIONS);

const AUTH_MODE = getAuthMode();

// ── WebSocket Auth Helper ──────────────────────────────────────────────────

async function authenticateWebSocket(
  req: IncomingMessage,
  socket: Socket
): Promise<boolean> {
  if (AUTH_MODE === "none") return true;

  const cookies = parseCookies(req.headers.cookie);
  const token = cookies["terminalx-session"];

  if (!token) {
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return false;
  }

  const payload = await verifyJwt(token);
  if (!payload) {
    socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
    socket.destroy();
    return false;
  }

  // Attach user info to request
  (req as any).user = payload;
  return true;
}

// ── Next.js App ─────────────────────────────────────────────────────────────

const dev = process.env.NODE_ENV !== "production";
const app = next({ dev, dir: path.resolve(__dirname, "..") });
const handle = app.getRequestHandler();

// ── WebSocket Servers (noServer mode) ───────────────────────────────────────

const terminalWss = new WebSocketServer({ noServer: true });
const logsWss = new WebSocketServer({ noServer: true });
const filesWss = new WebSocketServer({ noServer: true });

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
  const user = (req as any).user;
  if (user && (AUTH_MODE === "local" || AUTH_MODE === "oauth") && user.role === "user") {
    if (!sessionId.startsWith(`${user.username}-`)) {
      ws.close(1008, "Access denied");
      return;
    }
  }

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
  ws.send(
    JSON.stringify({ type: "pty-id", id: ptyInstance.id })
  );

  // PTY output -> WebSocket
  const dataHandler = ptyInstance.process.onData((data: string) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
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
      } catch {
        // Not JSON, treat as terminal input
      }
    }

    ptyInstance.process.write(data);
  });

  ws.on("close", () => {
    dataHandler.dispose();
    destroyPty(ptyInstance.id);
  });

  ws.on("error", () => {
    dataHandler.dispose();
    destroyPty(ptyInstance.id);
  });
});

// ── Log Tailing WebSocket Handler ───────────────────────────────────────────

logsWss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
  const url = parseUrl(req.url || "", true);
  const pathParts = (url.pathname || "").split("/");
  // /ws/logs/:encodedPath
  const encodedPath = pathParts[3];

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

// ── File Watcher WebSocket Handler ──────────────────────────────────────────

filesWss.on("connection", (ws: WebSocket) => {
  const watcher = watch(TERMINUS_ROOT, {
    ignored: [
      /(^|[\/\\])\../,          // dotfiles
      "**/node_modules/**",
      "**/.git/**",
      "**/.next/**",
      "**/dist/**",
      "**/build/**",
    ],
    persistent: true,
    ignoreInitial: true,
    depth: 5,
    awaitWriteFinish: {
      stabilityThreshold: 300,
      pollInterval: 100,
    },
  });

  const sendEvent = (event: string, filePath: string) => {
    if (ws.readyState === WebSocket.OPEN) {
      // Send path relative to TERMINUS_ROOT
      const relativePath = path.relative(TERMINUS_ROOT, filePath);
      ws.send(
        JSON.stringify({
          type: "file-event",
          event,
          path: relativePath,
          timestamp: Date.now(),
        })
      );
    }
  };

  watcher.on("add", (p: string) => sendEvent("add", p));
  watcher.on("change", (p: string) => sendEvent("change", p));
  watcher.on("unlink", (p: string) => sendEvent("unlink", p));
  watcher.on("addDir", (p: string) => sendEvent("addDir", p));
  watcher.on("unlinkDir", (p: string) => sendEvent("unlinkDir", p));

  ws.on("close", () => {
    watcher.close();
  });

  ws.on("error", () => {
    watcher.close();
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
    destroyAllPtys();
    destroyAllLogStreams();
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
