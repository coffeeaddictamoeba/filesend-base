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
  $SCRIPT_NAME <incoming_dir> --devices <id1,id2,...> [config.json] [--force[=server]]
  $SCRIPT_NAME <incoming_dir> --devices <id1> [config.json]

Behavior:
  - Starts the server container from crypto/<mode>/server
  - Runs one app container per selected device
  - Runs app containers from:
      crypto/<mode>/devices/<device_id>/<incoming_dir>

Notes:
  - Devices and security material must already be prepared by node-setup.sh

Examples:
  $SCRIPT_NAME incoming --devices dev1
  $SCRIPT_NAME incoming --devices dev1,dev2 setup.json
  $SCRIPT_NAME incoming --devices dev1,dev2 setup.json --force=server
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

for cmd in docker python3 grep sed id sleep mkdir; do
  require_cmd "$cmd"
done

INCOMING_DIR=""
CONFIG_FILE="setup.json"
FORCE_MODE=""
DEVICE_SELECTION_RAW=""

REPO_ROOT=""
SERVER_DOCKERFILE=""
SERVER_IMAGE=""
SERVER_CONTAINER_NAME=""
SERVER_WORKSPACE_DIR=""
SERVER_PORT_MAP=""
SERVER_MODE_ENV=""

APP_DOCKERFILE=""
APP_IMAGE=""
APP_CONTAINER_NAME=""
APP_WORKSPACE_DIR=""
APP_NETWORK=""
APP_ENCRYPT_RAW=""

ENCRYPT_MODE=""
MODE_CRYPTO_REL=""
MODE_CRYPTO_ROOT=""
SERVER_RUNTIME_DIR=""
DEVICES_ROOT=""

SERVER_WORKSPACE_ABS=""
APP_WORKSPACE_ABS=""

SELECTED_DEVICES=()

parse_args() {
  [[ $# -ge 1 ]] || { usage; exit 1; }

  INCOMING_DIR="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      *.json)
        CONFIG_FILE="$1"
        ;;
      --devices)
        shift
        [[ $# -gt 0 ]] || die "--devices requires a value"
        DEVICE_SELECTION_RAW="$1"
        ;;
      --force)
        FORCE_MODE="server"
        ;;
      --force=*)
        FORCE_MODE="${1#--force=}"
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
    shift
  done

  [[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"
  [[ -n "$DEVICE_SELECTION_RAW" ]] || die "--devices is required"

  case "$FORCE_MODE" in
    ""|server) ;;
    *) die "Invalid --force value for node-run.sh: $FORCE_MODE" ;;
  esac
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

image_exists() {
  docker image inspect "$1" >/dev/null 2>&1
}

remove_container_if_exists() {
  local name="$1"
  if container_exists "$name"; then
    log "Removing existing container: $name"
    docker rm -f "$name" >/dev/null
  fi
}

docker_build() {
  local image="$1" dockerfile="$2" uid_arg="$3" gid_arg="$4"
  log "Building image: $image"
  (
    cd "$REPO_ROOT"
    docker build --no-cache \
      -f "$dockerfile" \
      --build-arg "$uid_arg=$(id -u)" \
      --build-arg "$gid_arg=$(id -g)" \
      -t "$image" \
      .
  )
}

normalize_incoming_subpath() {
  local raw="$1"
  local clean="${raw#./}"
  clean="${clean#/}"
  clean="${clean%/}"
  [[ -n "$clean" ]] || die "Incoming directory must not be empty."
  [[ "$clean" != *".."* ]] || die "Incoming directory must not contain '..'"
  printf '%s\n' "$clean"
}

resolve_selected_devices() {
  IFS=',' read -r -a SELECTED_DEVICES <<< "$DEVICE_SELECTION_RAW"
  [[ ${#SELECTED_DEVICES[@]} -gt 0 ]] || die "No device ids parsed from --devices."
}

load_config() {
  REPO_ROOT="$(json_get "repo_root")"
  REPO_ROOT="${REPO_ROOT:-.}"

  SERVER_DOCKERFILE="$(json_get "server.dockerfile")"
  SERVER_IMAGE="$(json_get "server.image")"
  SERVER_CONTAINER_NAME="$(json_get "server.container_name")"
  SERVER_WORKSPACE_DIR="$(json_get "server.workspace_dir")"
  SERVER_PORT_MAP="$(json_get "server.port_map")"
  SERVER_MODE_ENV="$(json_get "server.env.SERVER_MODE")"

  APP_DOCKERFILE="$(json_get "app.dockerfile")"
  APP_IMAGE="$(json_get "app.image")"
  APP_CONTAINER_NAME="$(json_get "app.container_name")"
  APP_WORKSPACE_DIR="$(json_get "app.workspace_dir")"
  APP_NETWORK="$(json_get "app.network")"
  APP_ENCRYPT_RAW="$(json_get "app.encrypt")"

  SERVER_DOCKERFILE="${SERVER_DOCKERFILE:-Dockerfile.server}"
  SERVER_IMAGE="${SERVER_IMAGE:-filesend-server-dev}"
  SERVER_CONTAINER_NAME="${SERVER_CONTAINER_NAME:-filesend-server-dev}"
  SERVER_WORKSPACE_DIR="${SERVER_WORKSPACE_DIR:-server}"

  APP_DOCKERFILE="${APP_DOCKERFILE:-Dockerfile.sender}"
  APP_IMAGE="${APP_IMAGE:-filesend-app}"
  APP_CONTAINER_NAME="${APP_CONTAINER_NAME:-filesend-app}"
  APP_WORKSPACE_DIR="${APP_WORKSPACE_DIR:-.}"
  APP_NETWORK="${APP_NETWORK:-host}"

  ENCRYPT_MODE="$(normalize_encrypt_mode "${APP_ENCRYPT_RAW:-asymm}")"

  REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
  SERVER_WORKSPACE_ABS="$(cd "$REPO_ROOT/$SERVER_WORKSPACE_DIR" && pwd)"
  APP_WORKSPACE_ABS="$(cd "$REPO_ROOT/$APP_WORKSPACE_DIR" && pwd)"

  case "$ENCRYPT_MODE" in
    symm)
      MODE_CRYPTO_REL="crypto/symm"
      MODE_CRYPTO_ROOT="$REPO_ROOT/crypto/symm"
      ;;
    asymm|no)
      MODE_CRYPTO_REL="crypto/asymm"
      MODE_CRYPTO_ROOT="$REPO_ROOT/crypto/asymm"
      ;;
  esac

  SERVER_RUNTIME_DIR="$MODE_CRYPTO_ROOT/server"
  DEVICES_ROOT="$MODE_CRYPTO_ROOT/devices"
}

ensure_server_runtime_dir() {
  [[ -d "$SERVER_RUNTIME_DIR" ]] || die "Prepared server runtime dir not found: $SERVER_RUNTIME_DIR"
  [[ -f "$SERVER_RUNTIME_DIR/server_config" ]] || die "Missing mirrored server config: $SERVER_RUNTIME_DIR/server_config"

  if [[ -n "${SERVER_MODE_ENV:-}" ]]; then
    local runner_name
    runner_name="$([[ "${SERVER_MODE_ENV,,}" == "ws" ]] && echo "runserver_ws.py" || echo "runserver_https.py")"
    [[ -f "$SERVER_RUNTIME_DIR/$runner_name" ]] || warn "Expected runner not found in runtime dir: $SERVER_RUNTIME_DIR/$runner_name"
  fi
}

ensure_server_ready() {
  if [[ "$FORCE_MODE" == "server" || ! "$(image_exists "$SERVER_IMAGE" && echo yes || true)" == "yes" ]]; then
    docker_build "$SERVER_IMAGE" "$SERVER_DOCKERFILE" USER_UID USER_GID
  fi

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

  if [[ -f "$SERVER_RUNTIME_DIR/.env" ]]; then
    log "Found runtime .env at: $SERVER_RUNTIME_DIR/.env"
  fi

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

ensure_app_image() {
  if ! image_exists "$APP_IMAGE"; then
    docker_build "$APP_IMAGE" "$APP_DOCKERFILE" USER_ID GROUP_ID
  else
    log "Reusing existing app image: $APP_IMAGE"
  fi
}

run_app_for_device() {
  local device_id="$1"
  local incoming_subpath="$2"
  local device_dir="$DEVICES_ROOT/$device_id"
  local incoming_container_path="/workspace/${incoming_subpath}"
  local container_name="${APP_CONTAINER_NAME}-${device_id}"

  [[ -d "$device_dir" ]] || die "Device directory not found: $device_dir"
  [[ -f "$device_dir/filesend_config" ]] || die "Missing device config: $device_dir/filesend_config"
  [[ -d "$device_dir/$incoming_subpath" ]] || die "Missing device incoming dir: $device_dir/$incoming_subpath"

  remove_container_if_exists "$container_name"

  log "Running app container for device: $device_id"
  log "Using device dir bind mount: $device_dir -> /workspace"
  log "Command: filesend send $incoming_container_path"

  docker run -d \
    --name "$container_name" \
    --user "$(id -u):$(id -g)" \
    --network="$APP_NETWORK" \
    -v "$device_dir:/workspace" \
    -w /workspace \
    "$APP_IMAGE" \
    filesend send "$incoming_container_path" >/dev/null

  if container_running "$container_name"; then
    log "Started app container: $container_name"
  else
    warn "App container did not stay running: $container_name"
    docker logs "$container_name" || true
  fi
}

print_summary() {
  cat <<EOF

Run started.

Server container:
  name: $SERVER_CONTAINER_NAME
  image: $SERVER_IMAGE
  status: $(container_running "$SERVER_CONTAINER_NAME" && echo running || echo stopped)
  workspace: $SERVER_RUNTIME_DIR

Crypto mode:
  $ENCRYPT_MODE

Selected devices:
$(for d in "${SELECTED_DEVICES[@]}"; do printf '  - %s\n' "$d"; done)

Incoming directory name:
  $INCOMING_DIR

EOF
}

main() {
  parse_args "$@"
  load_config
  resolve_selected_devices

  local incoming_subpath
  incoming_subpath="$(normalize_incoming_subpath "$INCOMING_DIR")"

  ensure_server_ready
  ensure_app_image

  for device_id in "${SELECTED_DEVICES[@]}"; do
    run_app_for_device "$device_id" "$incoming_subpath"
  done

  print_summary
}

main "$@"