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

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `TERMINUS_ROOT` | `$HOME` | File browser root directory |
| `TERMINUS_SHELL` | `$SHELL` or `/bin/bash` | Default shell |
| `TERMINUS_READ_ONLY` | `false` | Disable file writes |
| `TERMINUS_SCROLLBACK` | `10000` | Terminal scrollback lines |
| `TERMINUS_MAX_SESSIONS` | `20` | Max concurrent PTY sessions |
| `TERMINUS_LOG_PATHS` | `/var/log,~/.pm2/logs` | Log directories |

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

## Skill routing

When the user's request matches an available skill, ALWAYS invoke it using the Skill
tool as your FIRST action. Do NOT answer directly, do NOT use other tools first.
The skill has specialized workflows that produce better results than ad-hoc answers.

Key routing rules:
- Product ideas, "is this worth building", brainstorming → invoke office-hours
- Bugs, errors, "why is this broken", 500 errors → invoke investigate
- Ship, deploy, push, create PR → invoke ship
- QA, test the site, find bugs → invoke qa
- Code review, check my diff → invoke review
- Update docs after shipping → invoke document-release
- Weekly retro → invoke retro
- Design system, brand → invoke design-consultation
- Visual audit, design polish → invoke design-review
- Architecture review → invoke plan-eng-review
- Save progress, checkpoint, resume → invoke checkpoint
- Code quality, health check → invoke health
