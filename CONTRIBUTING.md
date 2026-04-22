# Contributing to TerminalX

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
# Prerequisites: Node.js 20+, tmux, build tools for node-pty
# macOS: xcode-select --install
# Ubuntu: sudo apt install tmux build-essential

git clone https://github.com/dudhatparesh/terminalx-app.git
cd terminalx-app
npm install
npm run dev
```

Open http://localhost:3000.

## Running Tests

```bash
npm test              # Run all tests once
npm run test:watch    # Run tests in watch mode
npm run lint          # ESLint
npx tsc --noEmit      # TypeScript type check
```

## Project Structure

```
server/index.ts          Custom Node.js server (WebSocket + Next.js)
src/app/                 Next.js App Router (pages + API routes)
src/components/          React components
src/hooks/               Custom React hooks
src/lib/                 Server-side utilities
  auth.ts                JWT, password hashing, token revocation
  auth-config.ts         Auth mode configuration
  audit-log.ts           Structured security audit logging
  file-service.ts        File browser with path traversal prevention
  log-streamer.ts        Log file tailing
  pty-manager.ts         PTY process management
  session-scope.ts       Multi-user session access control
  tmux.ts                tmux session management
  users.ts               User CRUD (JSON file storage)
tests/                   Test suite (vitest)
```

## Making Changes

1. Fork the repo and create a branch from `main`.
2. Make your changes.
3. Add tests for any new functionality.
4. Ensure `npm test` and `npx tsc --noEmit` pass.
5. Open a pull request.

## Code Style

- TypeScript strict mode.
- Prefer explicit error handling over silent catches.
- All file paths must be validated against `TERMINUS_ROOT` to prevent traversal.
- Session names must match `[a-zA-Z0-9_.-]+`.
- Never spread `process.env` into spawned processes (use the safe env whitelist in `pty-manager.ts`).

## Security

If you find a security vulnerability, please report it privately via GitHub Security Advisories instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
