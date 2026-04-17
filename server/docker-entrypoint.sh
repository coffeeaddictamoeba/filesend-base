#!/usr/bin/env bash
set -Eeuo pipefail

WORKDIR="${WORKDIR:-/workspace}"
SERVER_MODE="${SERVER_MODE:-ws}"

cd "$WORKDIR"

die() { echo "[ERROR] $*" >&2; exit 1; }
log() { echo "[INFO]  $*"; }

ensure_file() {
  local path="$1"
  [[ -f "$path" ]] || die "Required file not found: $path"
}

load_env_file() {
  ensure_file ".env"
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
}

start_server() {
  ensure_file ".env"
  ensure_file "server_config"

  load_env_file

  case "$SERVER_MODE" in
    ws)
      log "Starting WebSocket server from workspace"
      exec python runserver_ws.py
      ;;
    https|http)
      log "Starting HTTPS server from workspace"
      exec python runserver_https.py
      ;;
    *)
      die "Unsupported SERVER_MODE: $SERVER_MODE"
      ;;
  esac
}

case "${1:-server}" in
  server)
    start_server
    ;;
  bash|sh)
    exec "$@"
    ;;
  *)
    exec "$@"
    ;;
esac