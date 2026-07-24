#!/usr/bin/env bash
set -euo pipefail

mkdir -p /app/data
chmod 700 /app/data

load_secret_file() {
  local target_name="$1"
  local file_variable_name="$2"
  local secret_file_path="${!file_variable_name:-}"
  if [ -z "$secret_file_path" ]; then
    return
  fi
  if [ ! -r "$secret_file_path" ]; then
    echo "Configured secret file is not readable: $file_variable_name" >&2
    exit 1
  fi
  printf -v "$target_name" '%s' "$(tr -d '\r\n' < "$secret_file_path")"
  export "$target_name"
}

load_secret_file TERMINALX_JWT_SECRET TERMINALX_JWT_SECRET_FILE
load_secret_file TERMINALX_ADMIN_PASSWORD TERMINALX_ADMIN_PASSWORD_FILE
load_secret_file TERMINALX_PASSWORD TERMINALX_PASSWORD_FILE

if [ -z "${TERMINALX_JWT_SECRET:-}" ]; then
  secret_file="/app/data/.terminalx-docker-jwt-secret"
  if [ ! -f "$secret_file" ]; then
    openssl rand -base64 48 > "$secret_file"
    chmod 600 "$secret_file"
  fi
  export TERMINALX_JWT_SECRET
  TERMINALX_JWT_SECRET="$(cat "$secret_file")"
fi

if [ "${TERMINALX_AUTH_MODE:-local}" = "local" ] &&
  [ -z "${TERMINALX_ADMIN_PASSWORD:-}" ] &&
  [ ! -s /app/data/users.json ]; then
  password_file="/app/data/.terminalx-docker-admin-password"
  if [ ! -f "$password_file" ]; then
    openssl rand -base64 24 | tr -d '/+=' | head -c 24 > "$password_file"
    chmod 600 "$password_file"
  fi
  export TERMINALX_ADMIN_PASSWORD
  TERMINALX_ADMIN_PASSWORD="$(cat "$password_file")"
  echo "Generated the initial admin password and stored it in $password_file." >&2
  echo "Retrieve it through an authenticated container console; it is never written to logs." >&2
fi

exec "$@"
