# TerminalX

A self-hosted terminal IDE for the browser. Manage tmux sessions, browse files, and tail logs — all from a beautiful web UI built with shadcn/ui.

## Features

- **Tabbed Terminals** — Open multiple tmux sessions in browser tabs
- **Session Management** — Create, attach, and kill tmux sessions from the sidebar
- **File Browser** — Navigate your server's filesystem with a tree view
- **Log Viewer** — Tail log files in real-time with color-coded levels
- **Resizable Panels** — Drag to arrange your workspace
- **Mobile Responsive** — Manage your server from your phone
- **Tailscale Ready** — Zero-config auth when used behind Tailscale

## Quick Start

```bash
# Clone and install
git clone https://github.com/dr-fusion/terminalx-app.git
cd terminalx-app
npm install

# Build and run
npm run build
npm run start
```

Open http://localhost:3000

### With Tailscale

```bash
npm run start &
tailscale serve --bg 3000
```

Now accessible at `https://your-machine.tailnet.ts.net`

## Development

```bash
npm run dev
```

## Configuration

All settings via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `TERMINUS_ROOT` | `$HOME` | File browser root |
| `TERMINUS_SHELL` | `$SHELL` | Default shell |
| `TERMINUS_READ_ONLY` | `false` | Read-only mode |
| `TERMINUS_MAX_SESSIONS` | `20` | Max terminal sessions |
| `TERMINUS_LOG_PATHS` | `/var/log,~/.pm2/logs` | Log directories to scan |

## Tech Stack

- [Next.js](https://nextjs.org) 16 + custom WebSocket server
- [shadcn/ui](https://ui.shadcn.com) + [Tailwind CSS](https://tailwindcss.com) 4
- [xterm.js](https://xtermjs.org) + [node-pty](https://github.com/nicedudeng/node-pty)
- [react-resizable-panels](https://github.com/bvaughn/react-resizable-panels)

## Requirements

- Node.js 20+
- tmux installed on the server
- Build tools for node-pty (`build-essential` on Debian/Ubuntu)

## License

MIT
