# TerminalX

[![CI](https://github.com/dudhatparesh/terminalx-app/actions/workflows/ci.yml/badge.svg)](https://github.com/dudhatparesh/terminalx-app/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A self-hosted terminal IDE for the browser. Manage tmux sessions, browse files, and tail logs from a single web UI.

One URL replaces your daily SSH workflow.

## Features

- **Tabbed Terminals** — Multiple tmux sessions in browser tabs with persistent state
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

## Quick Start

### Docker (recommended)

```bash
docker compose up
```

Open http://localhost:3000. That's it.

### From Source

```bash
git clone https://github.com/dudhatparesh/terminalx-app.git
cd terminalx-app
npm install
npm run build
npm run start
```

### With Tailscale

```bash
npm run start &
tailscale serve --bg 3000
```

Now accessible at `https://your-machine.tailnet.ts.net` with zero auth configuration needed.

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

## Configuration

All settings via environment variables. See [`.env.example`](.env.example) for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `TERMINUS_ROOT` | `$HOME` | File browser root |
| `TERMINUS_SHELL` | `$SHELL` | Default shell |
| `TERMINUS_READ_ONLY` | `false` | Read-only mode (disables terminal, uploads, session management) |
| `TERMINUS_MAX_SESSIONS` | `20` | Max terminal sessions |
| `TERMINUS_SCROLLBACK` | `10000` | tmux scrollback history lines |
| `TERMINUS_LOG_PATHS` | `/var/log,~/.pm2/logs` | Log directories to scan |
| `TERMINUS_RECORD_SESSIONS` | `false` | Record every PTY session to `data/recordings/*.jsonl` for replay (⚠ captures everything you type, including secrets) |
| `TERMINALX_AUTH_MODE` | `none` | Auth mode: `none`, `password`, `local`, `google` |
| `TERMINALX_GOOGLE_CLIENT_ID` | — | Google OAuth client ID (when `AUTH_MODE=google`) |
| `TERMINALX_GOOGLE_CLIENT_SECRET` | — | Google OAuth client secret |
| `TERMINALX_ALLOWED_EMAILS` | — | Comma-separated allowlist of Google emails; empty denies everyone |

## Authentication

TerminalX defaults to **no authentication** — designed to run behind Tailscale, a VPN, or on a trusted network.

For exposed deployments, enable auth:

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

## How It Compares

| Feature | TerminalX | ttyd/Wetty | Cockpit | code-server |
|---------|-----------|------------|---------|-------------|
| Web terminal | Yes | Yes | Yes | Yes |
| File browser | Yes | No | Yes | Yes (full IDE) |
| Log viewer | Yes | No | Yes | No |
| tmux sessions | Native | No | No | No |
| Persistent sessions | Yes (tmux) | No | No | Yes |
| Lightweight | Yes (~50MB) | Yes | Medium | Heavy (~1GB) |
| Self-contained | Yes | Yes | Yes | Yes |

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
- [xterm.js](https://xtermjs.org) (default) and [wterm](https://github.com/vercel-labs/wterm) (DOM/WASM renderer) + [node-pty](https://github.com/nicedudeng/node-pty)
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
- Structured audit logging for security events

See [CONTRIBUTING.md](CONTRIBUTING.md) for reporting security vulnerabilities.

## License

[MIT](LICENSE)
