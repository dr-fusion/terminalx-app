# TerminalX

[![CI](https://github.com/dudhatparesh/terminalx-app-mono/actions/workflows/ci.yml/badge.svg)](https://github.com/dudhatparesh/terminalx-app-mono/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A self-hosted terminal IDE for the browser. Manage tmux sessions, browse files, and tail logs from a single web UI.

One URL replaces your daily SSH workflow.

## Features

- **Tabbed Terminals** — Multiple tmux sessions in browser tabs with persistent state
- **Git Worktrees** — Start a session from a selected Git repo and optionally create a new branch worktree for parallel feature work
- **Dual Terminal Engines** — Toggle between xterm.js (default) and wterm (DOM-rendered, native Find-in-Page + selection)
- **AI CLI Sessions** — Spawn `claude` or `codex` CLI inside a persistent tmux session; your subscription, your PATH
- **Playground** — Zero-backend sandbox with an in-browser Bash running on WebAssembly (`@wterm/just-bash`)
- **Command Snippets** — Save and re-run multi-line shell commands; Insert (paste) or Run (paste + Enter) into the active terminal
- **Session Replay** — Optional byte-level recording of PTY sessions; play back at 0.5×–8× with a scrubber
- **File Browser** — Navigate your server's filesystem with a tree view
- **Log Viewer** — Tail log files in real-time with full ANSI rendering and browser Ctrl-F search
- **Resizable Panels** — Drag to arrange your workspace
- **Mobile Responsive** — Manage your server from your phone
- **Multi-user Support** — Optional user accounts with role-based session scoping
- **Google OAuth** — Sign in with a whitelisted Google account
- **Tailscale Ready** — Zero-config auth when used behind Tailscale
- **Drag & Drop Upload** — Upload files directly to your server
- **Telegram Bot** — Attach to your sessions from Telegram (one forum topic per session, inline keyboard, file transfer, chat/screen response modes, and local voice-note transcription). See `.env.example` for setup.

## Quick Start

### Fresh machine (from zero)

On a brand-new Linux host with nothing pre-installed, install the system prerequisites first, then run the setup script. The example below is for Debian/Ubuntu:

```bash
# 1. System packages: git, tmux, and node-pty build tools
sudo apt-get update
sudo apt-get install -y git tmux build-essential python3 curl ca-certificates

# 2. Node.js 20+ (NodeSource); skip if Node 20+ is already present
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# 3. (optional) PM2 for production process management
sudo npm install -g pm2

# 4. Clone and bootstrap
git clone https://github.com/dudhatparesh/terminalx-app-mono.git
cd terminalx-app-mono
npm run setup            # add --pm2 to run under PM2, --with-whisper for voice notes
```

On macOS, install the equivalents with Homebrew (`brew install git tmux node`) plus the Xcode command-line tools (`xcode-select --install`), then run steps 3–4.

> AI-CLI session kinds also need the `claude` and/or `codex` CLI installed on the host `PATH` **and logged in** — that login is shared across all TerminalX users on the machine. Install and authenticate them separately from this app.

### One-command setup

```bash
git clone https://github.com/dudhatparesh/terminalx-app-mono.git
cd terminalx-app-mono
npm run setup
```

The setup script checks Node.js/tmux, creates a secure `.env`, generates a JWT secret, creates first-start local admin credentials, installs dependencies, and builds the app.

To run under PM2:

```bash
npm run setup -- --pm2
```

To also install the local whisper.cpp binary and the small `tiny.en` model for Telegram voice notes:

```bash
npm run setup -- --with-whisper
```

### Docker

```bash
docker compose up
```

Open http://localhost:3000. That's it.

### From Source

```bash
git clone https://github.com/dudhatparesh/terminalx-app-mono.git
cd terminalx-app-mono
npm install
npm run build
npm run start
```

### With Tailscale

```bash
npm run start &
tailscale serve --bg 3000
```

Now accessible at `https://your-machine.tailnet.ts.net`. TerminalX still requires its own authentication.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Browser (xterm.js)                     │
├──────────────────────────────────────────────────────────┤
│                   WebSocket + HTTP                        │
├──────────────────────────────────────────────────────────┤
│              Custom Node.js Server                        │
│  ┌─────────────┐  ┌──────────┐  ┌────────────────────┐  │
│  │ /ws/terminal │  │ /ws/logs │  │ /ws/files           │  │
│  │  node-pty    │  │ tail -f  │  │ chokidar (shared)   │  │
│  │  + tmux      │  │          │  │                     │  │
│  └─────────────┘  └──────────┘  └────────────────────┘  │
├──────────────────────────────────────────────────────────┤
│              Next.js App Router (REST APIs)               │
│  /api/sessions  /api/files  /api/logs  /api/auth         │
├──────────────────────────────────────────────────────────┤
│              JWT Auth + Middleware                         │
└──────────────────────────────────────────────────────────┘
```

TerminalX runs **directly on your server** via node-pty + tmux. No SSH tunneling, no cloud dependencies. Terminal sessions persist through browser disconnects because they're backed by tmux.

### Local AI-session safety boundary

TerminalX-generated LocalTmux launches do not request Claude Code's permission-bypass mode or Codex's YOLO mode. The legacy Session API field that requested permission skipping is rejected before any worktree, port, tmux, metadata, or Telegram side effect.

LocalTmux is still trusted, single-host execution—not a Sandbox or a tenant-isolation boundary. The launched CLI inherits the host user's and Project's own harness configuration, hooks, credentials, filesystem access, and network access. Treat that configuration as local operator authority. Hosted bypass modes must be implemented separately inside a verified isolated Sandbox; they must not be added back as LocalTmux harness flags.

Tmux preserves already-running processes across application upgrades. After upgrading from a version that launched Claude with `--dangerously-skip-permissions` or Codex with `--yolo`, stop and recreate those managed AI sessions; changing the launcher cannot alter an existing process's arguments.

### Collaborative Team Sessions

Set `TERMINALX_MULTIPLAYER_ENABLED=true` and use the custom `npm run dev` or `npm start` server to activate the canonical Team Session Runtime and WebSocket transports. Canonical clients address the Session UUID—not a tmux name—at `/ws/team-sessions/:sessionId/terminal` and `/ws/team-sessions/:sessionId/events`. The HTTP API is under `/api/team-sessions`.

Enabling this mode disables the legacy direct `/ws/terminal/:tmuxName` upgrade path. Browser connections require same-origin cookie authentication; non-browser clients may use a Bearer header. Credentials are re-verified throughout long-lived connections, and every terminal mutation is checked against the current Control epoch and Runtime authorization generation. Each canonical Session runs on its own derived tmux server socket, so a tmux client cannot navigate into another Team Session. LocalTmux remains a trusted shared-host Runtime, not a Sandbox boundary: processes still run as the same host user and therefore require mutually trusted collaborators.

## Configuration

All settings via environment variables. See [`.env.example`](.env.example) for the full list.

| Variable                             | Default                               | Description                                                                                                          |
| ------------------------------------ | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `PORT`                               | `3000`                                | Server port                                                                                                          |
| `TERMINUS_HOST`                      | `127.0.0.1`                           | Bind host. Use `0.0.0.0` only with authentication or an explicit trusted-network setup                               |
| `TERMINUS_ROOT`                      | `$HOME`                               | File browser root                                                                                                    |
| `TERMINALX_WORKTREES_ROOT`           | `$TERMINUS_ROOT/.terminalx-worktrees` | Generated Git worktree directory; must remain under `TERMINUS_ROOT`                                                  |
| `TERMINUS_SHELL`                     | `$SHELL`                              | Default shell                                                                                                        |
| `TERMINUS_READ_ONLY`                 | `false`                               | Read-only mode (disables terminal, uploads, session management)                                                      |
| `TERMINUS_MAX_SESSIONS`              | `20`                                  | Max terminal sessions                                                                                                |
| `TERMINUS_SCROLLBACK`                | `10000`                               | tmux scrollback history lines                                                                                        |
| `TERMINUS_LOG_PATHS`                 | `/var/log,~/.pm2/logs`                | Log directories to scan                                                                                              |
| `TERMINUS_RECORD_SESSIONS`           | `false`                               | Record every PTY session to `data/recordings/*.jsonl` for replay (⚠ captures everything you type, including secrets) |
| `TERMINALX_MULTIPLAYER_ENABLED`      | `false`                               | Enable canonical Team Sessions/Runtime and disable the legacy direct terminal WebSocket                              |
| `TERMINALX_TEAM_SESSION_DB_PATH`     | `data/team-sessions.sqlite`           | Private SQLite state for Teams, Projects, Sessions, access, events, and Runtime outbox                               |
| `TERMINALX_TMUX_SOCKET_NAME`         | `terminalx-multiplayer`               | Namespace used to derive one isolated tmux server socket per canonical Team Session                                  |
| `TERMINALX_AUTH_MODE`                | `local`                               | Auth mode: `local`, `password`, or `google`. `none` is refused at startup                                            |
| `TERMINALX_PUBLIC_URL`               | —                                     | Canonical external URL for OAuth and redirects behind a proxy                                                        |
| `TERMINALX_TRUST_PROXY_HEADERS`      | `false`                               | Trust `X-Forwarded-*` headers only when a trusted proxy overwrites them                                              |
| `TERMINALX_GOOGLE_CLIENT_ID`         | —                                     | Google OAuth client ID (when `AUTH_MODE=google`)                                                                     |
| `TERMINALX_GOOGLE_CLIENT_SECRET`     | —                                     | Google OAuth client secret                                                                                           |
| `TERMINALX_ALLOWED_EMAILS`           | —                                     | Comma-separated allowlist of Google emails; empty denies everyone                                                    |
| `TERMINALX_TELEGRAM_MESSAGE_DB_PATH` | `data/telegram-messages.sqlite`       | Private SQLite audit log for inbound and outbound Telegram messages                                                  |

## Authentication

TerminalX defaults to local username/password auth and refuses to start without authentication. `TERMINALX_AUTH_MODE=none` is no longer supported.

Choose an auth mode:

```bash
# Shared password (simplest)
TERMINALX_AUTH_MODE=password TERMINALX_PASSWORD=your-password npm run start

# User accounts with roles
TERMINALX_AUTH_MODE=local TERMINALX_ADMIN_PASSWORD=your-password npm run start

# Google OAuth with email whitelist
TERMINALX_AUTH_MODE=google \
TERMINALX_GOOGLE_CLIENT_ID=<id>.apps.googleusercontent.com \
TERMINALX_GOOGLE_CLIENT_SECRET=<secret> \
TERMINALX_ALLOWED_EMAILS=me@example.com,teammate@example.com \
npm run start
```

In `local` mode, non-admin users can only access their own terminal sessions (prefixed with their username). In `google` mode, only emails in `TERMINALX_ALLOWED_EMAILS` can sign in — an empty list denies everyone.

## Telegram

Telegram can be configured either with environment variables or from the Settings page as an admin. Each Telegram forum topic maps to one tmux session. Topic responses can be set per session:

```text
/view chat
/view screen
/view off
```

The same response mode is available from the dashboard and Settings UI for sessions that already have a Telegram topic.

TerminalX keeps a durable audit trail of Telegram traffic from the moment this version is activated. Inbound webhook envelopes are committed before acknowledgement, and outbound send/edit attempts are recorded with their final Telegram result. Each row snapshots the bot, update, chat, topic, message, sender, reply, source and bound sessions, both tmux-session creation times, the native Claude/Codex transcript ID and path/offset, delivery status, and routing status. Reused tmux names and chat-scoped topic IDs remain distinguishable. An outbound row left `pending` means Telegram's final result could not be committed and should be investigated as an uncertain delivery.

The database defaults to `data/telegram-messages.sqlite`; override it with `TERMINALX_TELEGRAM_MESSAGE_DB_PATH` and preferably place custom paths in a dedicated private directory. It intentionally contains message text and raw Telegram update/result data, but redacts secret-like fields and stores uploaded-file metadata instead of bytes. TerminalX enforces mode `0600` on the database and its SQLite sidecars without changing permissions on an existing parent directory. Treat the database plus its `-wal` and `-shm` files as sensitive, keep them together for live backups, and monitor disk growth because records are retained indefinitely.

Authenticated admins can inspect it through `GET /api/telegram/messages`. Results default to 100 newest events and omit full content; use `includeContent=true` for full text/payloads and `includeSummary=true` for the more expensive route/anomaly summary. Inbound rows also show receipt count and `pending`/`processing`/`processed`/`failed` dispatch state. A 15-minute processing lease prevents overlapping server instances from executing the same update; after a crashed owner’s lease expires, a Telegram retry can reclaim it. Filters include `direction`, `operation`, `deliveryStatus`, `routingStatus`, `processingStatus`, `source`, `messageType`, `sessionId`, `botId`, `updateId`, `messageId`, `chatId`, `topicId`, `telegramUserId`, `from`, and `to`. Pagination uses the returned opaque `page.nextCursor`:

```text
/api/telegram/messages?sessionId=admin-alpha&topicId=77&includeSummary=true
/api/telegram/messages?routingStatus=mismatch&includeContent=true&limit=50
```

Voice notes sent inside a session topic are downloaded by the bot, converted with the bundled ffmpeg binary, transcribed locally with whisper.cpp, and sent to the bound tmux session as normal text input. Install the default small native model with:

```bash
npm run setup:whisper -- tiny.en
```

## How It Compares

| Feature             | TerminalX   | ttyd/Wetty | Cockpit | code-server    |
| ------------------- | ----------- | ---------- | ------- | -------------- |
| Web terminal        | Yes         | Yes        | Yes     | Yes            |
| File browser        | Yes         | No         | Yes     | Yes (full IDE) |
| Log viewer          | Yes         | No         | Yes     | No             |
| tmux sessions       | Native      | No         | No      | No             |
| Persistent sessions | Yes (tmux)  | No         | No      | Yes            |
| Lightweight         | Yes (~50MB) | Yes        | Medium  | Heavy (~1GB)   |
| Self-contained      | Yes         | Yes        | Yes     | Yes            |

## Development

```bash
npm run dev          # Start dev server (WebSocket + Next.js)
npm run dev:next     # Next.js only (for UI work, no WebSocket)
npm test             # Run tests
npm run lint         # ESLint
```

## Tech Stack

- [Next.js](https://nextjs.org) 16 + custom WebSocket server
- [shadcn/ui](https://ui.shadcn.com) + [Tailwind CSS](https://tailwindcss.com) 4
- [xterm.js](https://xtermjs.org) (default) and [wterm](https://github.com/vercel-labs/wterm) (DOM/WASM renderer) + [node-pty](https://github.com/microsoft/node-pty)
- [@wterm/just-bash](https://github.com/vercel-labs/wterm) for the in-browser Playground
- [react-resizable-panels](https://github.com/bvaughn/react-resizable-panels)

## Requirements

- Node.js 20+
- tmux installed on the server
- Build tools for node-pty (`build-essential` on Debian/Ubuntu, Xcode CLI tools on macOS)
- (optional) `claude` and/or `codex` CLI on the server's `PATH` and logged in — required for AI-CLI session kinds. Note: the CLI login is shared across all TerminalX users on the host.

## Security

- All file paths validated against `TERMINUS_ROOT` to prevent directory traversal
- Symlink resolution prevents filesystem escape
- JWT-based authentication with 24h expiry and persistent token revocation
- WebSocket Origin validation prevents cross-site hijacking
- PTY processes run with sanitized environment (server secrets not exposed)
- Rate limiting on login attempts
- Server startup fails if required auth secrets are missing
- Session deletion refuses to kill tmux sessions not created or tracked by TerminalX
- Structured audit logging for security events

See [CONTRIBUTING.md](CONTRIBUTING.md) for reporting security vulnerabilities.

## License

[MIT](LICENSE)
