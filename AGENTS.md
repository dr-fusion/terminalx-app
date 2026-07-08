<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.

<!-- END:nextjs-agent-rules -->

# TerminalX

Self-hosted terminal IDE for the browser. Manage tmux sessions, browse files, and tail logs from a modern web UI.

## Commands

```bash
npm run dev          # Start dev server (custom server with WebSocket + Next.js)
npm run dev:next     # Start Next.js only (no WebSocket — for UI development)
npm run build        # Production build
npm run start        # Production server
npm run lint         # ESLint
```

## Architecture

Custom Node.js server (`server/index.ts`) wraps Next.js to handle WebSocket upgrade:

- `/ws/terminal/:sessionId` — terminal I/O via node-pty + tmux
- `/ws/logs/:encodedPath` — log file tailing
- `/ws/files` — file watcher events

REST APIs in Next.js App Router (`src/app/api/`):

- `/api/sessions` — CRUD for tmux sessions
- `/api/files` — directory listing + file reading
- `/api/logs` — list available log files
- `/api/health` — health check

## Configuration

All via environment variables:

| Variable                | Default                 | Description                                                                                     |
| ----------------------- | ----------------------- | ----------------------------------------------------------------------------------------------- |
| `PORT`                  | `3000`                  | Server port                                                                                     |
| `TERMINUS_ROOT`         | `$HOME`                 | File browser root directory                                                                     |
| `TERMINUS_SHELL`        | `$SHELL` or `/bin/bash` | Default shell                                                                                   |
| `TERMINUS_READ_ONLY`    | `false`                 | Disable file writes                                                                             |
| `TERMINUS_SCROLLBACK`   | `10000`                 | Terminal scrollback lines                                                                       |
| `TERMINUS_MAX_SESSIONS` | `20`                    | Max concurrent PTY sessions                                                                     |
| `TERMINUS_LOG_PATHS`    | `/var/log,~/.pm2/logs`  | Log directories                                                                                 |
| `TERMINALX_PORT_BASE`   | `4100`                  | First port in the per-workspace allocation range (Conductor analog: `CONDUCTOR_PORT` pool base) |
| `TERMINALX_PORT_RANGE`  | `900`                   | Size of the per-workspace port range (`4100`–`4999` by default)                                 |

Workspace config (feature #5): a committed `.terminalx/settings.toml` at the
repo root declares a setup script, named run scripts, env vars, the default
session kind, and files to copy into a fresh worktree (`.env` "if you have
one"). Each managed workspace gets a unique injected `TERMINALX_PORT` (the
`CONDUCTOR_PORT` analog). `TERMINALX_PORT` is **not** a server config var — it
is the per-workspace value injected into each session. See
`docs/conductor-parity/designs/workspace-config.spec.md`.

## Tech Stack

- **Framework:** Next.js 16 (App Router) + custom server
- **UI:** shadcn/ui + Tailwind CSS 4
- **Terminal:** xterm.js + node-pty
- **WebSocket:** ws
- **Panels:** react-resizable-panels
- **Icons:** lucide-react

## Key Patterns

- xterm.js must be loaded client-only (`dynamic` with `ssr: false`)
- react-resizable-panels v4.9 uses `Group`/`Panel`/`Separator` (not PanelGroup/PanelResizeHandle)
- All file paths validated against TERMINUS_ROOT to prevent traversal
- tmux session names validated against `[a-zA-Z0-9_.-]`
- Dark theme only for v1
- Production restarts must not kill live tmux sessions. The `terminalx.service`
  systemd unit should use `KillMode=process` and stop only the TerminalX web
  server process, not the whole cgroup. Before restarting, verify with
  `systemctl show terminalx.service -p KillMode -p ExecStop`; after restarting,
  verify `tmux list-sessions` still shows existing sessions.
