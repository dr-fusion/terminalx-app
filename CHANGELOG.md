# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Pending hardening

- Move CSP from static header to nonce-based via middleware so `'unsafe-inline'`
  can be dropped from `script-src` and `style-src`. Requires cross-browser
  smoke testing to confirm Next.js / Tailwind / hydration all pick up the nonce.

## [0.1.0] — 2026-04-19

Initial public release.

### Added

- Custom Node.js server wrapping Next.js 16 with WebSocket support for
  terminal I/O (`/ws/terminal`), log tailing (`/ws/logs`), and file-watcher
  events (`/ws/files`).
- tmux session management with per-user scoping in `local` auth mode.
- File browser rooted at `TERMINUS_ROOT` with path-traversal + symlink
  protection.
- Log tailing of configured directories (`TERMINUS_LOG_PATHS`), restricted
  to admins in multi-user mode.
- Snippet library (`/api/snippets`) with per-user visibility.
- Session recording and replay (`TERMINUS_RECORD_SESSIONS=true`) with an
  0.5×–8× scrubber; recordings are per-user and retention is configurable
  via `TERMINUS_RECORDING_RETENTION_DAYS`.
- AI-CLI playground sessions (bash/claude/codex) with dangerous-permission
  toggle for Claude.
- Wterm integration for in-page command evaluation (engine toggle, ANSI
  logs, replay).
- Auth modes: `none`, `password`, `local` (multi-user + admin panel),
  `google` (OAuth with allow-list).
- JWT in HTTP-only cookies, rate-limited login and OAuth callback,
  WebSocket auth on upgrade, Origin validation, structured audit log.
- Docker image runs as non-root user with `tini` as PID 1 and a
  `HEALTHCHECK`.
- CI workflow (lint, typecheck, tests, build, Docker) and Dependabot.

### Security

- CSP, HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options`,
  `Referrer-Policy` set via Next.js headers.
- `TERMINALX_JWT_SECRET` never ships to client bundles (removed from
  `next.config.ts` `env` block).
- Data directories enforced to `0o700`; recording files written `0o600`.
