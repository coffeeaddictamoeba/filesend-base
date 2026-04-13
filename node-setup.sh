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
#     "network": "host",
#     "encrypt": "asymm" // or "symm"/"no"
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

if [[ $# -lt 1 || $# -gt 2 ]]; then usage; exit 1; fi

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
require_cmd chmod

# Minimal JSON helpers
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

normalize_connection_mode() {
  local mode
  mode="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    http|https) printf '%s\n' "http" ;;
    ws|wss)     printf '%s\n' "ws" ;;
    "")         printf '%s\n' "ws" ;;
    *) die "Unsupported server_connection.mode: $1 (expected http, https, ws, or wss)." ;;
  esac
}

normalize_encrypt_mode() {
  local mode
  mode="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    asymm|asymmetric|"") printf '%s\n' "asymm" ;;
    symm|symmetric)      printf '%s\n' "symm" ;;
    no|none|off)         printf '%s\n' "no" ;;
    *) die "Unsupported app.encrypt: $1 (expected asymm, symm, or no)." ;;
  esac
}

extract_host_from_url() {
  local raw="${1:-}"
  python3 - "$raw" <<'PY'
import sys
from urllib.parse import urlsplit

raw = (sys.argv[1] or "").strip()

if not raw:
    print("0.0.0.0")
    raise SystemExit(0)

candidate = raw
if "://" not in candidate:
    candidate = "dummy://" + raw

u = urlsplit(candidate)

if u.hostname:
    print(u.hostname)
else:
    raise SystemExit(f"Could not extract host from server_connection.url: {sys.argv[1]}")
PY
}

extract_port_from_url() {
  local raw="${1:-}"
  local normalized_mode="${2:-ws}"

  python3 - "$raw" "$normalized_mode" <<'PY'
import sys
from urllib.parse import urlsplit

raw = (sys.argv[1] or "").strip()
mode = (sys.argv[2] or "ws").strip().lower()

default_port = 8444 if mode == "ws" else 8443

if not raw:
    print(default_port)
    raise SystemExit(0)

candidate = raw
if "://" not in candidate:
    candidate = "dummy://" + raw

u = urlsplit(candidate)

if u.port is not None:
    print(u.port)
else:
    print(default_port)
PY
}

resolve_filesend_url() {
  local normalized_mode="$1"
  local raw_url="$2"
  local host
  local port

  host="$(extract_host_from_url "$raw_url")"
  port="$(extract_port_from_url "$raw_url" "$normalized_mode")"

  if [[ "$host" == *:* && "$host" != \[*\] ]]; then
    host="[$host]"
  fi

  case "$normalized_mode" in
    ws)   printf '%s\n' "wss://${host}:${port}" ;;
    http) printf '%s\n' "https://${host}:${port}/upload" ;;
    *) die "Cannot resolve filesend_config url for mode: $normalized_mode" ;;
  esac
}

set_config_value() {
  local file="$1"
  local key="$2"
  local value="$3"

  [[ -f "$file" ]] || die "Config file not found: $file"

  if grep -Eq "^[[:space:]]*${key}[[:space:]]*[:=]" "$file"; then
    sed -i -E "s|^([[:space:]]*${key}[[:space:]]*[:=][[:space:]]*).*$|\1${value}|" "$file"
  else
    printf '\n%s = %s\n' "$key" "$value" >> "$file"
  fi
}

remove_config_key() {
  local file="$1"
  local key="$2"
  [[ -f "$file" ]] || die "Config file not found: $file"
  sed -i -E "/^[[:space:]]*${key}[[:space:]]*[:=].*$/d" "$file"
}

rename_ini_section() {
  local file="$1"
  local old_section="$2"
  local new_section="$3"
  [[ -f "$file" ]] || die "Config file not found: $file"
  sed -i -E "s|^[[:space:]]*\[${old_section}\][[:space:]]*$|[${new_section}]|" "$file"
}

ensure_ini_section_name() {
  local file="$1"
  local target_section="$2"
  [[ -f "$file" ]] || die "Config file not found: $file"

  if grep -Eq "^[[:space:]]*\[inactive\][[:space:]]*$" "$file"; then
    sed -i -E "s|^[[:space:]]*\[inactive\][[:space:]]*$|[${target_section}]|" "$file"
  elif grep -Eq "^[[:space:]]*\[removed\][[:space:]]*$" "$file"; then
    sed -i -E "s|^[[:space:]]*\[removed\][[:space:]]*$|[${target_section}]|" "$file"
  fi
}

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
APP_ENCRYPT_RAW="$(json_get_nested_string "app" "encrypt")"

CONN_MODE="$(json_get_nested_string "server_connection" "mode")"
CONN_URL_RAW="$(json_get_nested_string "server_connection" "url")"

mapfile -t DEVICES < <(json_get_devices)

[[ -n "$SERVER_DOCKERFILE" ]] || SERVER_DOCKERFILE="Dockerfile.server"
[[ -n "$SERVER_IMAGE" ]] || SERVER_IMAGE="filesend-server-dev"
[[ -n "$SERVER_CONTAINER_NAME" ]] || SERVER_CONTAINER_NAME="filesend-server-dev"
[[ -n "$SERVER_WORKSPACE_DIR" ]] || SERVER_WORKSPACE_DIR="server"

[[ -n "$APP_DOCKERFILE" ]] || APP_DOCKERFILE="Dockerfile.sender"
[[ -n "$APP_IMAGE" ]] || APP_IMAGE="filesend-app"
[[ -n "$APP_CONTAINER_NAME" ]] || APP_CONTAINER_NAME="filesend-app"
[[ -n "$APP_WORKSPACE_DIR" ]] || APP_WORKSPACE_DIR="."
[[ -n "$APP_NETWORK" ]] || APP_NETWORK="host"

CONN_MODE="$(normalize_connection_mode "${CONN_MODE:-ws}")"
[[ -n "$SERVER_MODE_ENV" ]] || SERVER_MODE_ENV="$CONN_MODE"

ENCRYPT_MODE="$(normalize_encrypt_mode "${APP_ENCRYPT_RAW:-asymm}")"

SERVER_HOST="$(extract_host_from_url "${CONN_URL_RAW:-0.0.0.0}")"
SERVER_PORT="$(extract_port_from_url "${CONN_URL_RAW:-0.0.0.0}" "$CONN_MODE")"
CONN_URL="$(resolve_filesend_url "$CONN_MODE" "${CONN_URL_RAW:-0.0.0.0}")"

[[ -n "$SERVER_PORT_MAP" ]] || SERVER_PORT_MAP="${SERVER_PORT}:${SERVER_PORT}"

[[ ${#DEVICES[@]} -gt 0 ]] || die 'No devices found in config.json under "devices".'

REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
SERVER_WORKSPACE_ABS="$(cd "$REPO_ROOT/$SERVER_WORKSPACE_DIR" && pwd)"
APP_WORKSPACE_ABS="$(cd "$REPO_ROOT/$APP_WORKSPACE_DIR" && pwd)"

GENERATE_CONFIGS_SCRIPT="$REPO_ROOT/generate-configs.sh"
ROOT_FILESEND_CONFIG="$REPO_ROOT/filesend_config"
SERVER_CONFIG_PATH="$REPO_ROOT/server/server_config"

CRYPTO_ROOT="$REPO_ROOT/crypto"
ASYMM_ROOT="$CRYPTO_ROOT/asymm"
SYMM_ROOT="$CRYPTO_ROOT/symm"
SERVER_CRYPTO_DIR="$ASYMM_ROOT/server"
DEVICES_ROOT="$ASYMM_ROOT/devices"
CA_DIR="$ASYMM_ROOT/CA"

mkdir -p "$SERVER_CRYPTO_DIR" "$DEVICES_ROOT" "$CA_DIR" "$SYMM_ROOT"

LATEST_CA_BASENAME=""
LATEST_PUB_BASENAME=""
LATEST_SYM_BASENAME=""
LATEST_PR_BASENAME=""
LATEST_SERVER_CERT_BASENAME=""
LATEST_SERVER_KEY_BASENAME=""

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
log "  ENCRYPT_MODE=$ENCRYPT_MODE"
log "  CONN_MODE=$CONN_MODE"
log "  SERVER_HOST=$SERVER_HOST"
log "  SERVER_PORT=$SERVER_PORT"
log "  CONN_URL=$CONN_URL"
log "  ROOT_FILESEND_CONFIG=$ROOT_FILESEND_CONFIG"
log "  SERVER_CONFIG_PATH=$SERVER_CONFIG_PATH"
log "  DEVICES_COUNT=${#DEVICES[@]}"
for d in "${DEVICES[@]}"; do
  log "  DEVICE=$d"
done

generate_base_configs() {
  [[ -f "$GENERATE_CONFIGS_SCRIPT" ]] || die "generate-configs.sh not found: $GENERATE_CONFIGS_SCRIPT"

  log "Generating base configs via generate-configs.sh"
  (
    cd "$REPO_ROOT"
    chmod +x "$GENERATE_CONFIGS_SCRIPT"
    "$GENERATE_CONFIGS_SCRIPT"
  )

  [[ -f "$ROOT_FILESEND_CONFIG" ]] || die "Generated root filesend_config not found: $ROOT_FILESEND_CONFIG"
  [[ -f "$SERVER_CONFIG_PATH" ]] || die "Generated server/server_config not found: $SERVER_CONFIG_PATH"
}

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

prepare_server_material() {
  log "Collecting security material from server container."

  local ca_cert="" pub_key="" sym_key="" pr_key="" server_cert="" server_key=""

  ca_cert="$(find_latest_in_server_container 'ca_cert-*.pem' || true)"
  pub_key="$(find_latest_in_server_container 'pub*.bin' || true)"
  sym_key="$(find_latest_in_server_container 'sym*.bin' || true)"
  pr_key="$(find_latest_in_server_container 'pr*.bin' || true)"
  server_cert="$(find_latest_in_server_container 'server-*.crt' || true)"
  server_key="$(find_latest_in_server_container 'server-*.key' || true)"

  log "Resolved server material paths:"
  log "  ca_cert    = ${ca_cert:-<not found>}"
  log "  pub_key    = ${pub_key:-<not found>}"
  log "  sym_key    = ${sym_key:-<not found>}"
  log "  pr_key     = ${pr_key:-<not found>}"
  log "  server_cert= ${server_cert:-<not found>}"
  log "  server_key = ${server_key:-<not found>}"

  if [[ -n "$ca_cert" ]]; then
    copy_from_server_container_if_found "$ca_cert" "$CA_DIR/"
    LATEST_CA_BASENAME="$(basename "$ca_cert")"
  else
    warn "CA certificate was not found in the server container."
  fi

  if [[ -n "$pub_key" ]]; then
    copy_from_server_container_if_found "$pub_key" "$SERVER_CRYPTO_DIR/"
    LATEST_PUB_BASENAME="$(basename "$pub_key")"
  else
    warn "Public key was not found in the server container."
  fi

  if [[ -n "$sym_key" ]]; then
    copy_from_server_container_if_found "$sym_key" "$SYMM_ROOT/"
    LATEST_SYM_BASENAME="$(basename "$sym_key")"
  else
    warn "Symmetric key was not found in the server container."
  fi

  if [[ -n "$pr_key" ]]; then
    copy_from_server_container_if_found "$pr_key" "$SERVER_CRYPTO_DIR/"
    LATEST_PR_BASENAME="$(basename "$pr_key")"
  else
    warn "Private key was not found in the server container."
  fi

  if [[ -n "$server_cert" ]]; then
    copy_from_server_container_if_found "$server_cert" "$SERVER_CRYPTO_DIR/"
    LATEST_SERVER_CERT_BASENAME="$(basename "$server_cert")"
  else
    warn "Server TLS certificate was not found in the server container."
  fi

  if [[ -n "$server_key" ]]; then
    copy_from_server_container_if_found "$server_key" "$SERVER_CRYPTO_DIR/"
    LATEST_SERVER_KEY_BASENAME="$(basename "$server_key")"
  else
    warn "Server TLS key was not found in the server container."
  fi
}

apply_encrypt_mode_to_root_filesend_config() {
  local cfg="$1"

  case "$ENCRYPT_MODE" in
    asymm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "asymmetric"
      if [[ -n "${LATEST_PUB_BASENAME:-}" ]]; then
        set_config_value "$cfg" "pub_key_path" "crypto/asymm/server/${LATEST_PUB_BASENAME}"
      fi
      if [[ -n "${LATEST_PR_BASENAME:-}" ]]; then
        set_config_value "$cfg" "pr_key_path" "crypto/asymm/server/${LATEST_PR_BASENAME}"
      fi
      remove_config_key "$cfg" "sym_key_path"
      ;;
    symm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "symmetric"
      if [[ -n "${LATEST_SYM_BASENAME:-}" ]]; then
        set_config_value "$cfg" "sym_key_path" "crypto/symm/${LATEST_SYM_BASENAME}"
      fi
      remove_config_key "$cfg" "pub_key_path"
      remove_config_key "$cfg" "pr_key_path"
      ;;
    no)
      if grep -Eq '^[[:space:]]*\[crypto\][[:space:]]*$' "$cfg"; then
        rename_ini_section "$cfg" "crypto" "inactive"
      elif grep -Eq '^[[:space:]]*\[removed\][[:space:]]*$' "$cfg"; then
        rename_ini_section "$cfg" "removed" "inactive"
      fi
      ;;
  esac
}

update_root_filesend_config() {
  [[ -f "$ROOT_FILESEND_CONFIG" ]] || die "Missing root filesend_config: $ROOT_FILESEND_CONFIG"

  if [[ -n "${LATEST_CA_BASENAME:-}" ]]; then
    set_config_value "$ROOT_FILESEND_CONFIG" "cert_path" "crypto/asymm/CA/${LATEST_CA_BASENAME}"
  else
    warn "No CA cert available for root filesend_config."
  fi

  apply_encrypt_mode_to_root_filesend_config "$ROOT_FILESEND_CONFIG"

  if [[ "$CONN_MODE" == "ws" ]]; then
    set_config_value "$ROOT_FILESEND_CONFIG" "use_ws" "true"
  else
    set_config_value "$ROOT_FILESEND_CONFIG" "use_ws" "false"
  fi

  set_config_value "$ROOT_FILESEND_CONFIG" "url" "$CONN_URL"

  log "Updated root filesend config: $ROOT_FILESEND_CONFIG"
  log "  encrypt mode = $ENCRYPT_MODE"
  log "  url          = $CONN_URL"
}

update_generated_server_config() {
  [[ -f "$SERVER_CONFIG_PATH" ]] || die "Missing generated server config: $SERVER_CONFIG_PATH"

  set_config_value "$SERVER_CONFIG_PATH" "host" "$SERVER_HOST"
  set_config_value "$SERVER_CONFIG_PATH" "port" "$SERVER_PORT"

  if [[ -n "${LATEST_SERVER_CERT_BASENAME:-}" ]]; then
    set_config_value "$SERVER_CONFIG_PATH" "cert_path" "../crypto/asymm/server/${LATEST_SERVER_CERT_BASENAME}"
  fi

  if [[ -n "${LATEST_SERVER_KEY_BASENAME:-}" ]]; then
    set_config_value "$SERVER_CONFIG_PATH" "key_path" "../crypto/asymm/server/${LATEST_SERVER_KEY_BASENAME}"
  fi

  log "Updated server config: $SERVER_CONFIG_PATH"
  log "  host = $SERVER_HOST"
  log "  port = $SERVER_PORT"
}

apply_encrypt_mode_to_device_config() {
  local cfg="$1"
  local device_id="$2"
  local device_dir="$3"

  case "$ENCRYPT_MODE" in
    asymm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "asymmetric"

      if [[ -n "${LATEST_PUB_BASENAME:-}" && -f "$SERVER_CRYPTO_DIR/$LATEST_PUB_BASENAME" ]]; then
        cp "$SERVER_CRYPTO_DIR/$LATEST_PUB_BASENAME" "$device_dir/"
        set_config_value "$cfg" "pub_key_path" "$LATEST_PUB_BASENAME"
      else
        warn "No public key available for device $device_id."
      fi

      remove_config_key "$cfg" "pr_key_path"
      remove_config_key "$cfg" "sym_key_path"
      ;;
    symm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "symmetric"

      if [[ -n "${LATEST_SYM_BASENAME:-}" && -f "$SYMM_ROOT/$LATEST_SYM_BASENAME" ]]; then
        cp "$SYMM_ROOT/$LATEST_SYM_BASENAME" "$device_dir/"
        set_config_value "$cfg" "sym_key_path" "$LATEST_SYM_BASENAME"
      else
        warn "No symmetric key available for device $device_id."
      fi

      remove_config_key "$cfg" "pub_key_path"
      remove_config_key "$cfg" "pr_key_path"
      ;;
    no)
      if grep -Eq '^[[:space:]]*\[crypto\][[:space:]]*$' "$cfg"; then
        rename_ini_section "$cfg" "crypto" "inactive"
      elif grep -Eq '^[[:space:]]*\[removed\][[:space:]]*$' "$cfg"; then
        rename_ini_section "$cfg" "removed" "inactive"
      fi
      ;;
  esac
}

prepare_device_dir() {
  local device_id="$1"
  local device_dir="$DEVICES_ROOT/$device_id"
  local device_cfg="$device_dir/filesend_config"

  mkdir -p "$device_dir"
  cp "$ROOT_FILESEND_CONFIG" "$device_cfg"

  if [[ -n "${LATEST_CA_BASENAME:-}" && -f "$CA_DIR/$LATEST_CA_BASENAME" ]]; then
    cp "$CA_DIR/$LATEST_CA_BASENAME" "$device_dir/"
    set_config_value "$device_cfg" "cert_path" "$LATEST_CA_BASENAME"
  else
    warn "No CA cert available for device $device_id."
  fi

  apply_encrypt_mode_to_device_config "$device_cfg" "$device_id" "$device_dir"

  if [[ "$CONN_MODE" == "ws" ]]; then
    set_config_value "$device_cfg" "use_ws" "true"
  else
    set_config_value "$device_cfg" "use_ws" "false"
  fi

  set_config_value "$device_cfg" "url" "$CONN_URL"
  set_config_value "$device_cfg" "device_id" "$device_id"

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

Generated configs:
  $ROOT_FILESEND_CONFIG
  $SERVER_CONFIG_PATH

Connection:
  host = $SERVER_HOST
  port = $SERVER_PORT
  mode = $CONN_MODE
  url  = $CONN_URL

Encryption:
  app.encrypt = $ENCRYPT_MODE

Generated directories:
  $CRYPTO_ROOT
  $CA_DIR
  $SERVER_CRYPTO_DIR
  $DEVICES_ROOT
  $SYMM_ROOT

Devices prepared:
$(for d in "${DEVICES[@]}"; do printf '  - %s\n' "$d"; done)

EOF
}

log "Generating base configs."
generate_base_configs

log "Building server image."
build_server_image

log "Running server detached."
run_server_detached

log "Preparing server material."
prepare_server_material

log "Updating generated root filesend_config."
update_root_filesend_config

log "Updating generated server/server_config."
update_generated_server_config

log "Starting device directory preparation."
log "Devices root: $DEVICES_ROOT"
log "Devices count: ${#DEVICES[@]}"

for device_id in "${DEVICES[@]}"; do
  log "Preparing device: $device_id"
  prepare_device_dir "$device_id"
done

print_summary

if [[ "$MODE" == "--multiple" ]]; then
  log "Multiple-node mode selected."
  log "The server container is running in detached mode."
  log "The app container was NOT started by design."
  echo
  echo "To add a new device later, re-run:"
  echo "  ./$SCRIPT_NAME --multiple <config-with-new-device.json>"
  exit 0
fi

build_app_image
run_app_interactive