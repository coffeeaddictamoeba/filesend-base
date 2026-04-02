#!/usr/bin/env bash
set -Eeuo pipefail

# node-setup.sh
#
# Usage:
#   ./node-setup.sh --one config.json
#   ./node-setup.sh --multiple config.json
#
# Expected JSON shape (example):
# {
#   "repo_root": ".",
#   "server": {
#     "dockerfile": "Dockerfile.server",
#     "image": "filesend-server-dev",
#     "container_name": "filesend-server-dev",
#     "workspace_dir": "server",
#     "port_map": "8444:8444",
#     "env": {
#       "SERVER_MODE": "ws"
#     }
#   },
#   "app": {
#     "dockerfile": "Dockerfile.sender",
#     "image": "filesend-app",
#     "container_name": "filesend-app",
#     "workspace_dir": ".",
#     "network": "host"
#   },
#   "server_connection": {
#     "mode": "ws",
#     "url": "127.0.0.1:8444"
#   },
#   "devices": [
#     { "id": "device_1" },
#     { "id": "device_2" }
#   ]
# }
#
# Notes:
# - Re-running the script with only a new device in "devices" will create/update
#   only that device directory; existing device directories are left in place.
# - The script assumes the server container generates security material on startup.

SCRIPT_NAME="$(basename "$0")"

die()  { 
  echo "[ERROR] $*" >&2; exit 1
}
warn() { 
  echo "[WARN] $*"  >&2 
}
log()  { 
  echo "[INFO] $*" 
}

cleanup_on_error() {
  local exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    warn "Script failed with exit code $exit_code."
  fi
}
trap cleanup_on_error EXIT

usage() {
  cat <<EOF
Usage:
  $SCRIPT_NAME --one <config.json>
  $SCRIPT_NAME --multiple <config.json>

Modes:
  --one       Build/run the server container in detached mode, prepare configs/keys,
              then build and start the app container interactively for testing.
  --multiple  Build/run only the server container in detached mode, prepare configs/keys for devices.
EOF
}

MODE=""
CONFIG_FILE="setup.json"

if [[ $# -ne 1 ]]; then usage; exit 1; fi

case "$1" in
  --one|--multiple) MODE="$1" ;;
  *) usage; die "Unknown mode: $1" ;;
esac

if [[ $# -eq 2 ]]; then 
  CONFIG_FILE="$2"
fi

[[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"

require_cmd() { 
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1" 
}

require_cmd docker
require_cmd python3
require_cmd awk
require_cmd sed
require_cmd grep
require_cmd find
require_cmd cp
require_cmd mkdir
require_cmd date

# Minimal JSON helpers
# Minimal JSON helpers (using python stdlib, no jq dependency)
json_get_string() {
  local key="$1"
  python3 - "$CONFIG_FILE" "$key" <<'PY'
import json, sys
path, key = sys.argv[1], sys.argv[2]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
value = data.get(key, "")
print(value if isinstance(value, str) else "")
PY
}

json_get_nested_string() {
  local section="$1"
  local key="$2"
  python3 - "$CONFIG_FILE" "$section" "$key" <<'PY'
import json, sys
path, section, key = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
obj = data.get(section, {})
if isinstance(obj, dict):
    value = obj.get(key, "")
    print(value if isinstance(value, str) else "")
else:
    print("")
PY
}

json_get_server_env_string() {
  local key="$1"
  python3 - "$CONFIG_FILE" "$key" <<'PY'
import json, sys
path, key = sys.argv[1], sys.argv[2]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
value = data.get("server", {}).get("env", {}).get(key, "")
print(value if isinstance(value, str) else "")
PY
}

json_get_devices() {
  python3 - "$CONFIG_FILE" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
for dev in data.get("devices", []):
    dev_id = dev.get("id")
    if isinstance(dev_id, str):
        print(dev_id)
PY
}

# Read config
REPO_ROOT="$(json_get_string "repo_root")"
[[ -n "$REPO_ROOT" ]] || REPO_ROOT="."

SERVER_DOCKERFILE="$(json_get_nested_string "server" "dockerfile")"
SERVER_IMAGE="$(json_get_nested_string "server" "image")"
SERVER_CONTAINER_NAME="$(json_get_nested_string "server" "container_name")"
SERVER_WORKSPACE_DIR="$(json_get_nested_string "server" "workspace_dir")"
SERVER_PORT_MAP="$(json_get_nested_string "server" "port_map")"
SERVER_MODE_ENV="$(json_get_server_env_string "SERVER_MODE")"

APP_DOCKERFILE="$(json_get_nested_string "app" "dockerfile")"
APP_IMAGE="$(json_get_nested_string "app" "image")"
APP_CONTAINER_NAME="$(json_get_nested_string "app" "container_name")"
APP_WORKSPACE_DIR="$(json_get_nested_string "app" "workspace_dir")"
APP_NETWORK="$(json_get_nested_string "app" "network")"

CONN_MODE="$(json_get_nested_string "server_connection" "mode")"
CONN_URL="$(json_get_nested_string "server_connection" "url")"

mapfile -t DEVICES < <(json_get_devices)

[[ -n "$SERVER_DOCKERFILE" ]] || SERVER_DOCKERFILE="Dockerfile.server"
[[ -n "$SERVER_IMAGE" ]]      || SERVER_IMAGE="filesend-server-dev"
[[ -n "$SERVER_CONTAINER_NAME" ]] || SERVER_CONTAINER_NAME="filesend-server-dev"
[[ -n "$SERVER_WORKSPACE_DIR" ]]  || SERVER_WORKSPACE_DIR="server"
[[ -n "$SERVER_PORT_MAP" ]] || SERVER_PORT_MAP="8444:8444"
[[ -n "$SERVER_MODE_ENV" ]] || SERVER_MODE_ENV="${CONN_MODE:-ws}"

[[ -n "$APP_DOCKERFILE" ]] || APP_DOCKERFILE="Dockerfile.sender"
[[ -n "$APP_IMAGE" ]]      || APP_IMAGE="filesend-app"
[[ -n "$APP_CONTAINER_NAME" ]] || APP_CONTAINER_NAME="filesend-app"
[[ -n "$APP_WORKSPACE_DIR" ]]  || APP_WORKSPACE_DIR="."
[[ -n "$APP_NETWORK" ]] || APP_NETWORK="host"

[[ -n "$CONN_MODE" ]] || CONN_MODE="ws"
[[ -n "$CONN_URL" ]]  || CONN_URL="127.0.0.1:8444"

[[ ${#DEVICES[@]} -gt 0 ]] || die "No devices found in config.json under \"devices\"."

log "Resolved config:"
log "  REPO_ROOT=$REPO_ROOT"
log "  SERVER_DOCKERFILE=$SERVER_DOCKERFILE"
log "  SERVER_IMAGE=$SERVER_IMAGE"
log "  SERVER_CONTAINER_NAME=$SERVER_CONTAINER_NAME"
log "  SERVER_WORKSPACE_DIR=$SERVER_WORKSPACE_DIR"
log "  SERVER_PORT_MAP=$SERVER_PORT_MAP"
log "  SERVER_MODE_ENV=$SERVER_MODE_ENV"
log "  APP_DOCKERFILE=$APP_DOCKERFILE"
log "  APP_IMAGE=$APP_IMAGE"
log "  APP_CONTAINER_NAME=$APP_CONTAINER_NAME"
log "  APP_WORKSPACE_DIR=$APP_WORKSPACE_DIR"
log "  APP_NETWORK=$APP_NETWORK"
log "  CONN_MODE=$CONN_MODE"
log "  CONN_URL=$CONN_URL"
log "  DEVICES_COUNT=${#DEVICES[@]}"
for d in "${DEVICES[@]}"; do
  log "  DEVICE=$d"
done

REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
SERVER_WORKSPACE_ABS="$(cd "$REPO_ROOT/$SERVER_WORKSPACE_DIR" && pwd)"
APP_WORKSPACE_ABS="$(cd "$REPO_ROOT/$APP_WORKSPACE_DIR" && pwd)"

TEMPLATE_CONFIG="$REPO_ROOT/filesend_config"
[[ -f "$TEMPLATE_CONFIG" ]] || die "Template filesend_config was not found in repo root: $TEMPLATE_CONFIG"

# ./
# └── crypto/
#     ├── asymm/
#     │   ├── CA/
#     │   ├── devices/
#     │   │   ├── <device_id_1>/
#     │   │   ├── <device_id_2>/
#     │   │   └── <device_id_N>/
#     │   └── server/
#     └── symm/
CRYPTO_ROOT="$REPO_ROOT/crypto"
ASYMM_ROOT="$CRYPTO_ROOT/asymm"
SYMM_ROOT="$CRYPTO_ROOT/symm"
SERVER_CRYPTO_DIR="$ASYMM_ROOT/server"
DEVICES_ROOT="$ASYMM_ROOT/devices"
CA_DIR="$ASYMM_ROOT/CA"

mkdir -p "$SERVER_CRYPTO_DIR" "$DEVICES_ROOT" "$CA_DIR" "$SYMM_ROOT"

# Docker helpers
container_exists() {
  local name="$1"
  docker ps -a --format '{{.Names}}' | grep -Fxq "$name"
}

container_running() {
  local name="$1"
  docker ps --format '{{.Names}}' | grep -Fxq "$name"
}

remove_container_if_exists() {
  local name="$1"
  if container_exists "$name"; then
    log "Removing existing container: $name"
    docker rm -f "$name" >/dev/null
  fi
}

build_server_image() {
  log "Building server image: $SERVER_IMAGE"
  (
    cd "$REPO_ROOT"
    docker build \
      -f "$SERVER_DOCKERFILE" \
      --build-arg USER_UID="$(id -u)" \
      --build-arg USER_GID="$(id -g)" \
      -t "$SERVER_IMAGE" \
      .
  )
}

run_server_detached() {
  remove_container_if_exists "$SERVER_CONTAINER_NAME"
  log "Starting server container in detached mode: $SERVER_CONTAINER_NAME"
  log "  image:      $SERVER_IMAGE"
  log "  port map:   $SERVER_PORT_MAP"
  log "  workspace:  $SERVER_WORKSPACE_ABS:/workspace"
  log "  mode env:   SERVER_MODE=$SERVER_MODE_ENV"

  cd "$REPO_ROOT/server/"

  local container_id
  container_id="$(
    docker run -d \
      --name "$SERVER_CONTAINER_NAME" \
      -p "$SERVER_PORT_MAP" \
      -v "$SERVER_WORKSPACE_ABS:/workspace" \
      -e "SERVER_MODE=$SERVER_MODE_ENV" \
      "$SERVER_IMAGE"
  )"

  log "Server container id: $container_id"
  sleep 5

  if container_running "$SERVER_CONTAINER_NAME"; then
    log "Server container is running."
    return 0
  fi

  warn "Server container exited shortly after startup."
  warn "Container status:"
  docker ps -a --filter "name=^${SERVER_CONTAINER_NAME}$" || true

  warn "Server logs:"
  docker logs "$SERVER_CONTAINER_NAME" || true

  die "Server container did not stay running."
}

build_app_image() {
  log "Building app image: $APP_IMAGE"
  (
    cd "$REPO_ROOT"
    docker build \
      -f "$APP_DOCKERFILE" \
      --build-arg USER_ID="$(id -u)" \
      --build-arg GROUP_ID="$(id -g)" \
      -t "$APP_IMAGE" \
      .
  )
}

run_app_interactive() {
  remove_container_if_exists "$APP_CONTAINER_NAME"
  log "Starting app container interactively: $APP_CONTAINER_NAME"
  log "You will be dropped into the app container shell."
  docker run --rm -it \
    --name "$APP_CONTAINER_NAME" \
    --user "$(id -u):$(id -g)" \
    --network="$APP_NETWORK" \
    -v "$APP_WORKSPACE_ABS:/workspace" \
    -w /workspace \
    "$APP_IMAGE"
}

# Security material handling
find_latest_in_server_container() {
  local pattern="$1"
  docker exec "$SERVER_CONTAINER_NAME" sh -lc "
    for base in /workspace/keys /workspace/certs /workspace /root /home /tmp; do
      if [ -d \"\$base\" ]; then
        find \"\$base\" -type f -name '$pattern' 2>/dev/null
      fi
    done | sort | tail -n 1
  " 2>/dev/null | tr -d '\r' || true
}

copy_from_server_container_if_found() {
  local container_path="$1"
  local host_path="$2"

  if [[ -n "$container_path" ]]; then
    docker cp "$SERVER_CONTAINER_NAME:$container_path" "$host_path" >/dev/null
    return 0
  fi
  return 1
}

set_config_value() {
  local file="$1"
  local key="$2"
  local value="$3"

  if grep -Eq "^[[:space:]]*${key}[[:space:]]*[:=]" "$file"; then
    sed -i -E "s|^([[:space:]]*${key}[[:space:]]*[:=][[:space:]]*).*$|\1${value}|" "$file"
  elif grep -Eq "^[[:space:]]*${key}[[:space:]]*$" "$file"; then
    sed -i -E "s|^([[:space:]]*${key}[[:space:]]*)$|\1 ${value}|" "$file"
  else
    printf '%s = %s\n' "$key" "$value" >> "$file"
  fi
}

prepare_server_material() {
  log "Collecting security material from server container."

  local ca_cert="" pub_key="" sym_key="" pr_key="" server_cfg=""

  ca_cert="$(find_latest_in_server_container 'ca_cert-*.pem' || true)"
  pub_key="$(find_latest_in_server_container 'pub*.bin' || true)"
  sym_key="$(find_latest_in_server_container 'sym*.bin' || true)"
  server_cfg="$(find_latest_in_server_container 'server_config' || true)"

  log "Resolved server material paths:"
  log "  ca_cert   = ${ca_cert:-<not found>}"
  log "  pub_key   = ${pub_key:-<not found>}"
  log "  sym_key   = ${sym_key:-<not found>}"
  log "  server_cfg= ${server_cfg:-<not found>}"

  if [[ -n "$ca_cert" ]]; then
    copy_from_server_container_if_found "$ca_cert" "$CA_DIR/"
    copy_from_server_container_if_found "$ca_cert" "$SERVER_CRYPTO_DIR/"
  else
    warn "CA certificate was not found in the server container."
  fi

  if [[ -n "$pub_key" ]]; then
    copy_from_server_container_if_found "$pub_key" "$SERVER_CRYPTO_DIR/"
  else
    warn "Public key was not found in the server container."
  fi

  if [[ -n "$sym_key" ]]; then
    copy_from_server_container_if_found "$sym_key" "$SERVER_CRYPTO_DIR/"
  else
    warn "Symmetric key was not found in the server container."
  fi

  if [[ -n "$server_cfg" ]]; then
    copy_from_server_container_if_found "$server_cfg" "$SERVER_CRYPTO_DIR/"
  else
    warn "server_config was not found in the server container."
  fi

  LATEST_CA_BASENAME=""
  LATEST_PUB_BASENAME=""
  LATEST_SYM_BASENAME=""
  LATEST_PR_BASENAME=""

  if [[ -n "$ca_cert" ]]; then
    LATEST_CA_BASENAME="$(basename "$ca_cert")"
  fi

  if [[ -n "$pub_key" ]]; then
    LATEST_PUB_BASENAME="$(basename "$pub_key")"
  fi

  if [[ -n "$sym_key" ]]; then
    LATEST_SYM_BASENAME="$(basename "$sym_key")"
  fi

  log "Collected material basenames:"
  log "  LATEST_CA_BASENAME=${LATEST_CA_BASENAME:-<empty>}"
  log "  LATEST_PUB_BASENAME=${LATEST_PUB_BASENAME:-<empty>}"
  log "  LATEST_SYM_BASENAME=${LATEST_SYM_BASENAME:-<empty>}"

  return 0
}

prepare_device_dir() {
  local device_id="$1"
  local device_dir="$DEVICES_ROOT/$device_id"

  mkdir -p "$device_dir"
  cp "$TEMPLATE_CONFIG" "$device_dir/filesend_config"

  if [[ -n "${LATEST_CA_BASENAME:-}" && -f "$CA_DIR/$LATEST_CA_BASENAME" ]]; then
    cp "$CA_DIR/$LATEST_CA_BASENAME" "$device_dir/"
    set_config_value "$device_dir/filesend_config" "cert_path" "$LATEST_CA_BASENAME"
  else
    warn "No CA cert available for device $device_id."
  fi

  if [[ -n "${LATEST_PUB_BASENAME:-}" && -f "$SERVER_CRYPTO_DIR/$LATEST_PUB_BASENAME" ]]; then
    cp "$SERVER_CRYPTO_DIR/$LATEST_PUB_BASENAME" "$device_dir/"
    set_config_value "$device_dir/filesend_config" "pub_key_path" "$LATEST_PUB_BASENAME"
  elif [[ -n "${LATEST_SYM_BASENAME:-}" && -f "$SERVER_CRYPTO_DIR/$LATEST_SYM_BASENAME" ]]; then
    cp "$SERVER_CRYPTO_DIR/$LATEST_SYM_BASENAME" "$device_dir/"
    set_config_value "$device_dir/filesend_config" "sym_key_path" "$LATEST_SYM_BASENAME"
  elif [[ -n "${LATEST_PR_BASENAME:-}" && -f "$SERVER_CRYPTO_DIR/$LATEST_PR_BASENAME" ]]; then
    cp "$SERVER_CRYPTO_DIR/$LATEST_PR_BASENAME" "$device_dir/"
    set_config_value "$device_dir/filesend_config" "sym_key_path" "$LATEST_PR_BASENAME"
  fi

  set_config_value "$device_dir/filesend_config" "mode" "$CONN_MODE"
  set_config_value "$device_dir/filesend_config" "url" "$CONN_URL"

  set_config_value "$device_dir/filesend_config" "device_id" "$device_id"

  log "Prepared device directory: $device_dir"
}

print_summary() {
  cat <<EOF

Setup completed.

Repo root:
  $REPO_ROOT

Server container:
  name: $SERVER_CONTAINER_NAME
  image: $SERVER_IMAGE
  status: $(container_running "$SERVER_CONTAINER_NAME" && echo running || echo stopped)

Generated directories:
  $CRYPTO_ROOT
  $SERVER_CRYPTO_DIR
  $DEVICES_ROOT

Devices prepared:
$(for d in "${DEVICES[@]}"; do printf '  - %s\n' "$d"; done)

Connection settings written into each filesend_config:
  mode = $CONN_MODE
  url  = $CONN_URL

EOF
}

# Main
echo "[INFO] Building server image."
build_server_image
echo "[INFO] Running server detached."
run_server_detached
echo "[INFO] Preparing server material."
prepare_server_material

cd .. # return from server/

log "Starting device directory preparation."
log "Devices root: $DEVICES_ROOT"
log "Devices count: ${#DEVICES[@]}"

for device_id in "${DEVICES[@]}"; do
  log "Preparing device: $device_id"
  prepare_device_dir "$device_id"
done

print_summary

if [[ "$MODE" == "--multiple" ]]; then
  echo "[INFO] Multiple-node mode selected."
  echo "[INFO] The server container is running in detached mode."
  echo "[INFO] The app container was NOT started by design."
  echo
  echo "To add a new device later, re-run:"
  echo "  ./$SCRIPT_NAME --multiple <config-with-new-device.json>"
  exit 0
fi

build_app_image
run_app_interactive
