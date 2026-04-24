#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"

die()  { echo "[ERROR] $*" >&2; exit 1; }
warn() { echo "[WARN]  $*" >&2; }
log()  { echo "[INFO]  $*"; }

trap 'ec=$?; (( ec == 0 )) || warn "Script failed with exit code $ec."' EXIT

usage() {
  cat <<EOF
Usage:
  $SCRIPT_NAME [--json <config.json>]

Behavior:
  - Starts the server container from crypto/<mode>/server

Defaults:
  --json setup.json
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

for cmd in docker python3 grep id sleep pwd dirname basename; do
  require_cmd "$cmd"
done

CONFIG_FILE="setup.json"

REPO_ROOT=""
SERVER_IMAGE=""
SERVER_CONTAINER_NAME=""
SERVER_PORT_MAP=""
SERVER_MODE_ENV=""

APP_ENCRYPT_RAW=""
ENCRYPT_MODE=""
MODE_CRYPTO_ROOT=""
SERVER_RUNTIME_DIR=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json)
        shift
        [[ $# -gt 0 ]] || die "--json requires a value"
        CONFIG_FILE="$1"
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *.json)
        die "Positional config file is no longer supported. Use --json <config.json>"
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
    shift
  done

  [[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"
}

json_get() {
  local path="$1"
  python3 - "$CONFIG_FILE" "$path" <<'PY'
import json, sys

cfg_path, dotted = sys.argv[1], sys.argv[2]
with open(cfg_path, "r", encoding="utf-8") as f:
    data = json.load(f)

cur = data
for part in dotted.split("."):
    if isinstance(cur, dict) and part in cur:
        cur = cur[part]
    else:
        print("")
        raise SystemExit(0)

print(cur if isinstance(cur, str) else "")
PY
}

normalize_encrypt_mode() {
  local mode
  mode="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    ""|asymm|asymmetric) printf '%s\n' "asymm" ;;
    symm|symmetric)      printf '%s\n' "symm" ;;
    no|none|off)         printf '%s\n' "no" ;;
    *) die "Unsupported app.encrypt: $1" ;;
  esac
}

container_exists() {
  docker ps -a --format '{{.Names}}' | grep -Fxq "$1"
}

container_running() {
  docker ps --format '{{.Names}}' | grep -Fxq "$1"
}

remove_container_if_exists() {
  local name="$1"
  if container_exists "$name"; then
    log "Removing existing container: $name"
    docker rm -f "$name" >/dev/null
  fi
}

load_config() {
  REPO_ROOT="$(json_get "repo_root")"
  REPO_ROOT="${REPO_ROOT:-.}"

  SERVER_IMAGE="$(json_get "server.image")"
  SERVER_CONTAINER_NAME="$(json_get "server.container_name")"
  SERVER_PORT_MAP="$(json_get "server.port_map")"
  SERVER_MODE_ENV="$(json_get "server.env.SERVER_MODE")"

  APP_ENCRYPT_RAW="$(json_get "app.encrypt")"

  SERVER_IMAGE="${SERVER_IMAGE:-filesend-server-dev}"
  SERVER_CONTAINER_NAME="${SERVER_CONTAINER_NAME:-filesend-server-dev}"
  SERVER_PORT_MAP="${SERVER_PORT_MAP:-8444:8444}"
  SERVER_MODE_ENV="${SERVER_MODE_ENV:-ws}"

  ENCRYPT_MODE="$(normalize_encrypt_mode "${APP_ENCRYPT_RAW:-asymm}")"

  REPO_ROOT="$(cd "$REPO_ROOT" && pwd -P)"

  case "$ENCRYPT_MODE" in
    symm)
      MODE_CRYPTO_ROOT="$REPO_ROOT/crypto/symm"
      ;;
    asymm|no)
      MODE_CRYPTO_ROOT="$REPO_ROOT/crypto/asymm"
      ;;
  esac

  SERVER_RUNTIME_DIR="$MODE_CRYPTO_ROOT/server"
}

ensure_server_runtime_dir() {
  [[ -d "$SERVER_RUNTIME_DIR" ]] || die "Prepared server runtime dir not found: $SERVER_RUNTIME_DIR"
  [[ -f "$SERVER_RUNTIME_DIR/server_config" ]] || die "Missing mirrored server config: $SERVER_RUNTIME_DIR/server_config"

  local runner_name
  runner_name="$([[ "${SERVER_MODE_ENV,,}" == "ws" ]] && echo "runserver_ws.py" || echo "runserver_https.py")"

  if [[ ! -f "$SERVER_RUNTIME_DIR/$runner_name" ]]; then
    warn "Expected runner not found in runtime dir: $SERVER_RUNTIME_DIR/$runner_name"
  fi
}

start_server() {
  ensure_server_runtime_dir
  remove_container_if_exists "$SERVER_CONTAINER_NAME"

  log "Starting server container: $SERVER_CONTAINER_NAME"
  log "Using server runtime dir: $SERVER_RUNTIME_DIR"

  local docker_args=(
    run -d
    --name "$SERVER_CONTAINER_NAME"
    -p "$SERVER_PORT_MAP"
    -v "$SERVER_RUNTIME_DIR:/workspace"
    -w /workspace
    -e "WORKDIR=/workspace"
    -e "SERVER_MODE=$SERVER_MODE_ENV"
  )

  docker_args+=("$SERVER_IMAGE")

  docker "${docker_args[@]}" >/dev/null

  sleep 5

  if container_running "$SERVER_CONTAINER_NAME"; then
    log "Server container is running"
    return
  fi

  warn "Server container exited shortly after startup."
  docker ps -a --filter "name=^${SERVER_CONTAINER_NAME}$" || true
  docker logs "$SERVER_CONTAINER_NAME" || true
  die "Server container did not stay running."
}

print_summary() {
  cat <<EOF

Server run started.

Server container:
  name: $SERVER_CONTAINER_NAME
  image: $SERVER_IMAGE
  status: $(container_running "$SERVER_CONTAINER_NAME" && echo running || echo stopped)
  workspace: $SERVER_RUNTIME_DIR

Crypto mode:
  $ENCRYPT_MODE

EOF
}

main() {
  parse_args "$@"
  load_config
  start_server
  print_summary
}

main "$@"