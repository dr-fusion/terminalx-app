#!/usr/bin/env bash
# TerminalX — Start Script
# Usage: ./start.sh [--no-auth] [--password] [--local]

set -e

# ── cd to project root (where this script lives) ───────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Defaults ────────────────────────────────────────────────────────────────
PORT="${PORT:-3456}"
TERMINUS_HOST="${TERMINUS_HOST:-0.0.0.0}"
TERMINUS_ROOT="${TERMINUS_ROOT:-$HOME}"
TERMINUS_SHELL="${TERMINUS_SHELL:-$SHELL}"
TERMINUS_MAX_SESSIONS="${TERMINUS_MAX_SESSIONS:-20}"
TERMINUS_READ_ONLY="${TERMINUS_READ_ONLY:-false}"
TERMINUS_LOG_PATHS="${TERMINUS_LOG_PATHS:-/var/log,~/.pm2/logs}"
TERMINALX_ADMIN_PASSWORD="REDACTED"
# ── Auth Mode ───────────────────────────────────────────────────────────────
AUTH_MODE="${TERMINALX_AUTH_MODE:-local}"

if [ "$1" = "--no-auth" ]; then
  AUTH_MODE="none"
elif [ "$1" = "--password" ]; then
  AUTH_MODE="password"
elif [ "$1" = "--local" ]; then
  AUTH_MODE="local"
fi

# ── Prompt for credentials if not set ───────────────────────────────────────
if [ "$AUTH_MODE" = "password" ] && [ -z "$TERMINALX_PASSWORD" ]; then
  echo -n "Enter shared password: "
  read -rs TERMINALX_PASSWORD
  echo
  export TERMINALX_PASSWORD
fi

if [ "$AUTH_MODE" = "local" ]; then
  TERMINALX_ADMIN_USERNAME="${TERMINALX_ADMIN_USERNAME:-admin}"
  if [ -z "$TERMINALX_ADMIN_PASSWORD" ]; then
    echo -n "Enter admin password for '$TERMINALX_ADMIN_USERNAME': "
    read -rs TERMINALX_ADMIN_PASSWORD
    echo
    export TERMINALX_ADMIN_PASSWORD
  fi
  export TERMINALX_ADMIN_USERNAME
fi

# ── JWT Secret (auto-generate if not set) ───────────────────────────────────
if [ -z "$TERMINALX_JWT_SECRET" ] && [ "$AUTH_MODE" != "none" ]; then
  SECRET_FILE=".terminalx-secret"
  if [ -f "$SECRET_FILE" ]; then
    TERMINALX_JWT_SECRET=$(cat "$SECRET_FILE")
  else
    TERMINALX_JWT_SECRET=$(openssl rand -base64 48 | tr -d '/+=' | head -c 48)
    echo "$TERMINALX_JWT_SECRET" > "$SECRET_FILE"
    chmod 600 "$SECRET_FILE"
    echo "Generated JWT secret → $SECRET_FILE"
  fi
  export TERMINALX_JWT_SECRET
fi

# ── Export all config ───────────────────────────────────────────────────────
export PORT
export TERMINUS_HOST
export TERMINUS_ROOT
export TERMINUS_SHELL
export TERMINUS_MAX_SESSIONS
export TERMINUS_READ_ONLY
export TERMINUS_LOG_PATHS
export TERMINALX_AUTH_MODE="$AUTH_MODE"
export NODE_ENV=production

# ── Build if needed ─────────────────────────────────────────────────────────
if [ ! -d ".next" ] || [ "$1" = "--build" ]; then
  echo "Building TerminalX..."
  npm run build
fi

# ── Print config ────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════╗"
echo "║           TerminalX                  ║"
echo "╠══════════════════════════════════════╣"
echo "║  URL:    http://$TERMINUS_HOST:$PORT"
echo "║  Auth:   $AUTH_MODE"
echo "║  Root:   $TERMINUS_ROOT"
echo "║  Shell:  $TERMINUS_SHELL"
if [ "$AUTH_MODE" = "local" ]; then
echo "║  Admin:  $TERMINALX_ADMIN_USERNAME"
fi
echo "╚══════════════════════════════════════╝"
echo ""

# ── Start server ────────────────────────────────────────────────────────────
exec npx tsx server/index.ts
