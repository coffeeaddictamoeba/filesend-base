#!/usr/bin/env bash
set -Eeuo pipefail

# Sets up a local filesend Docker test environment from a JSON config.
# It generates base config files, builds and starts the server container,
# collects server-generated crypto/TLS material, updates shared and per-device
# filesend configs, and prepares device directories under crypto/.
#
# In --multiple mode, it prepares or refreshes only the server side and device
# configuration material and leaves the server running.
#
# In --one mode, it also builds and runs the app container and starts:
#   filesend send <incoming_directory>
# using the provided incoming directory inside the mounted workspace.
#
# By default, the script reuses existing containers, images, configs, and
# device data where possible. Use --force to rebuild all or selected parts.

SCRIPT_NAME="$(basename "$0")"

die()  { echo "[ERROR] $*" >&2; exit 1; }
warn() { echo "[WARN]  $*" >&2; }
log()  { echo "[INFO]  $*"; }

trap 'ec=$?; (( ec == 0 )) || warn "Script failed with exit code $ec."' EXIT

usage() {
  cat <<EOF
Usage:
  $SCRIPT_NAME --one <incoming_directory> [config.json] [--force[=all|server|devices]]
  $SCRIPT_NAME --multiple <incoming_directory> [config.json] [--force[=all|server|devices]]

Modes:
  --one       Build/run server if needed, prepare configs/keys, then build/run
              the app container with: filesend send <incoming_directory>
  --multiple  Build/run only the server side if needed and prepare device configs

Force options:
  --force           Same as --force=all
  --force=all       Rebuild everything
  --force=server    Rebuild server only; do not rebuild device dirs
  --force=devices   Rebuild device dirs only; do not rebuild server

Examples:
  $SCRIPT_NAME --one ./incoming
  $SCRIPT_NAME --one ./incoming setup.json
  $SCRIPT_NAME --one ./incoming setup.json --force
  $SCRIPT_NAME --multiple ./incoming config.json --force=devices
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

for cmd in docker python3 grep sed find cp mkdir chmod id sleep rm; do
  require_cmd "$cmd"
done

MODE=""
INCOMING_DIR=""
CONFIG_FILE="setup.json"
FORCE_MODE=""   # "", "all", "server", "devices"

parse_args() {
  [[ $# -ge 2 ]] || { usage; exit 1; }

  case "$1" in
    --one|--multiple) MODE="$1" ;;
    *) usage; die "Unknown mode: $1" ;;
  esac

  INCOMING_DIR="$2"
  [[ -n "$INCOMING_DIR" ]] || die "Incoming directory must not be empty."
  shift 2

  for arg in "$@"; do
    case "$arg" in
      --force)
        FORCE_MODE="all"
        ;;
      --force=*)
        FORCE_MODE="${arg#--force=}"
        ;;
      *.json)
        CONFIG_FILE="$arg"
        ;;
      *)
        die "Unknown argument: $arg"
        ;;
    esac
  done

  [[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"

  case "$FORCE_MODE" in
    ""|all|server|devices) ;;
    *) die "Invalid --force value: $FORCE_MODE" ;;
  esac
}

should_force_all()     { [[ "$FORCE_MODE" == "all" ]]; }
should_force_server()  { [[ "$FORCE_MODE" == "all" || "$FORCE_MODE" == "server" ]]; }
should_force_devices() { [[ "$FORCE_MODE" == "all" || "$FORCE_MODE" == "devices" ]]; }

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

json_list_devices() {
  python3 - "$CONFIG_FILE" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

for dev in data.get("devices", []):
    dev_id = dev.get("id")
    if isinstance(dev_id, str) and dev_id:
        print(dev_id)
PY
}

normalize_connection_mode() {
  local mode
  mode="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    ""|ws|wss)   printf '%s\n' "ws" ;;
    http|https)  printf '%s\n' "http" ;;
    *) die "Unsupported server_connection.mode: $1 (expected http, https, ws, or wss)." ;;
  esac
}

normalize_encrypt_mode() {
  local mode
  mode="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    ""|asymm|asymmetric) printf '%s\n' "asymm" ;;
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

candidate = raw if "://" in raw else f"dummy://{raw}"
u = urlsplit(candidate)

if u.hostname:
    print(u.hostname)
else:
    raise SystemExit(f"Could not extract host from server_connection.url: {raw}")
PY
}

extract_port_from_url() {
  local raw="${1:-}"
  local mode="${2:-ws}"

  python3 - "$raw" "$mode" <<'PY'
import sys
from urllib.parse import urlsplit

raw = (sys.argv[1] or "").strip()
mode = (sys.argv[2] or "ws").strip().lower()
default_port = 8444 if mode == "ws" else 8443

if not raw:
    print(default_port)
    raise SystemExit(0)

candidate = raw if "://" in raw else f"dummy://{raw}"
u = urlsplit(candidate)
print(u.port if u.port is not None else default_port)
PY
}

resolve_filesend_url() {
  local mode="$1"
  local raw_url="$2"
  local host port

  host="$(extract_host_from_url "$raw_url")"
  port="$(extract_port_from_url "$raw_url" "$mode")"

  if [[ "$host" == *:* && "$host" != \[*\] ]]; then
    host="[$host]"
  fi

  case "$mode" in
    ws)   printf '%s\n' "wss://${host}:${port}" ;;
    http) printf '%s\n' "https://${host}:${port}/upload" ;;
    *) die "Cannot resolve filesend URL for mode: $mode" ;;
  esac
}

set_config_value() {
  local file="$1" key="$2" value="$3"
  [[ -f "$file" ]] || die "Config file not found: $file"

  if grep -Eq "^[[:space:]]*${key}[[:space:]]*[:=]" "$file"; then
    sed -i -E "s|^([[:space:]]*${key}[[:space:]]*[:=][[:space:]]*).*$|\1${value}|" "$file"
  else
    printf '\n%s = %s\n' "$key" "$value" >> "$file"
  fi
}

remove_config_key() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || die "Config file not found: $file"
  sed -i -E "/^[[:space:]]*${key}[[:space:]]*[:=].*$/d" "$file"
}

rename_ini_section() {
  local file="$1" old="$2" new="$3"
  [[ -f "$file" ]] || die "Config file not found: $file"
  sed -i -E "s|^[[:space:]]*\[${old}\][[:space:]]*$|[${new}]|" "$file"
}

ensure_ini_section_name() {
  local file="$1" target="$2"
  [[ -f "$file" ]] || die "Config file not found: $file"

  if grep -Eq "^[[:space:]]*\[inactive\][[:space:]]*$" "$file"; then
    sed -i -E "s|^[[:space:]]*\[inactive\][[:space:]]*$|[${target}]|" "$file"
  elif grep -Eq "^[[:space:]]*\[removed\][[:space:]]*$" "$file"; then
    sed -i -E "s|^[[:space:]]*\[removed\][[:space:]]*$|[${target}]|" "$file"
  fi
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

generate_base_configs() {
  [[ -f "$GENERATE_CONFIGS_SCRIPT" ]] || die "generate-configs.sh not found: $GENERATE_CONFIGS_SCRIPT"

  log "Generating base configs"
  (
    cd "$REPO_ROOT"
    chmod +x "$GENERATE_CONFIGS_SCRIPT"
    "$GENERATE_CONFIGS_SCRIPT"
  )

  [[ -f "$ROOT_FILESEND_CONFIG" ]] || die "Generated root filesend_config not found: $ROOT_FILESEND_CONFIG"
  [[ -f "$SERVER_CONFIG_PATH" ]] || die "Generated server/server_config not found: $SERVER_CONFIG_PATH"
}

run_server_detached() {
  remove_container_if_exists "$SERVER_CONTAINER_NAME"

  log "Starting server container: $SERVER_CONTAINER_NAME"
  docker run -d \
    --name "$SERVER_CONTAINER_NAME" \
    -p "$SERVER_PORT_MAP" \
    -v "$SERVER_WORKSPACE_ABS:/workspace" \
    -e "SERVER_MODE=$SERVER_MODE_ENV" \
    "$SERVER_IMAGE" >/dev/null

  sleep 5

  if container_running "$SERVER_CONTAINER_NAME"; then
    log "Server container is running"
    return
  fi

  warn "Server container exited shortly after startup."
  warn "Container status:"
  docker ps -a --filter "name=^${SERVER_CONTAINER_NAME}$" || true
  warn "Server logs:"
  docker logs "$SERVER_CONTAINER_NAME" || true
  die "Server container did not stay running."
}

ensure_server_available() {
  if should_force_server || ! container_exists "$SERVER_CONTAINER_NAME"; then
    log "Rebuilding server (force=${FORCE_MODE:-none})"
    docker_build "$SERVER_IMAGE" "$SERVER_DOCKERFILE" USER_UID USER_GID
    run_server_detached
    SERVER_REFRESHED="true"
    return
  fi

  log "Reusing existing server container"
  if ! container_running "$SERVER_CONTAINER_NAME"; then
    log "Starting existing server container"
    docker start "$SERVER_CONTAINER_NAME" >/dev/null
    sleep 2
  fi
  SERVER_REFRESHED="false"
}

find_latest_in_server_container() {
  local pattern="$1"
  docker exec "$SERVER_CONTAINER_NAME" sh -lc "
    for base in /workspace/keys /workspace/certs /workspace /root /home /tmp; do
      [ -d \"\$base\" ] && find \"\$base\" -type f -name '$pattern' 2>/dev/null
    done | sort | tail -n 1
  " 2>/dev/null | tr -d '\r' || true
}

copy_from_server_container_if_found() {
  local container_path="$1" dest_dir="$2"
  [[ -n "$container_path" ]] || return 1
  docker cp "$SERVER_CONTAINER_NAME:$container_path" "$dest_dir/" >/dev/null
}

load_existing_server_material_basenames() {
  LATEST_CA_BASENAME="$(find "$CA_DIR" -maxdepth 1 -type f -name 'ca_cert-*.pem'   -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
  LATEST_PUB_BASENAME="$(find "$SERVER_CRYPTO_DIR" -maxdepth 1 -type f -name 'pub*.bin'        -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
  LATEST_PR_BASENAME="$(find "$SERVER_CRYPTO_DIR" -maxdepth 1 -type f -name 'pr*.bin'          -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
  LATEST_SERVER_CERT_BASENAME="$(find "$SERVER_CRYPTO_DIR" -maxdepth 1 -type f -name 'server-*.crt' -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
  LATEST_SERVER_KEY_BASENAME="$(find "$SERVER_CRYPTO_DIR" -maxdepth 1 -type f -name 'server-*.key'  -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
  LATEST_SYM_BASENAME="$(find "$SYMM_ROOT" -maxdepth 1 -type f -name 'sym*.bin'                -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
}

prepare_server_material() {
  log "Collecting security material from server container"

  local ca_cert pub_key sym_key pr_key server_cert server_key
  ca_cert="$(find_latest_in_server_container 'ca_cert-*.pem')"
  pub_key="$(find_latest_in_server_container 'pub*.bin')"
  sym_key="$(find_latest_in_server_container 'sym*.bin')"
  pr_key="$(find_latest_in_server_container 'pr*.bin')"
  server_cert="$(find_latest_in_server_container 'server-*.crt')"
  server_key="$(find_latest_in_server_container 'server-*.key')"

  [[ -n "$ca_cert" ]]     && copy_from_server_container_if_found "$ca_cert" "$CA_DIR"                && LATEST_CA_BASENAME="$(basename "$ca_cert")"               || warn "CA certificate not found"
  [[ -n "$pub_key" ]]     && copy_from_server_container_if_found "$pub_key" "$SERVER_CRYPTO_DIR"     && LATEST_PUB_BASENAME="$(basename "$pub_key")"              || warn "Public key not found"
  [[ -n "$sym_key" ]]     && copy_from_server_container_if_found "$sym_key" "$SYMM_ROOT"             && LATEST_SYM_BASENAME="$(basename "$sym_key")"              || warn "Symmetric key not found"
  [[ -n "$pr_key" ]]      && copy_from_server_container_if_found "$pr_key" "$SERVER_CRYPTO_DIR"      && LATEST_PR_BASENAME="$(basename "$pr_key")"                || warn "Private key not found"
  [[ -n "$server_cert" ]] && copy_from_server_container_if_found "$server_cert" "$SERVER_CRYPTO_DIR" && LATEST_SERVER_CERT_BASENAME="$(basename "$server_cert")"  || warn "Server TLS certificate not found"
  [[ -n "$server_key" ]]  && copy_from_server_container_if_found "$server_key" "$SERVER_CRYPTO_DIR"  && LATEST_SERVER_KEY_BASENAME="$(basename "$server_key")"    || warn "Server TLS key not found"
}

ensure_server_material() {
  if [[ "$SERVER_REFRESHED" == "true" ]]; then
    prepare_server_material
    return
  fi

  load_existing_server_material_basenames
  log "Reusing existing server crypto/TLS material"
}

apply_encrypt_mode_to_root_config() {
  local cfg="$1"

  case "$ENCRYPT_MODE" in
    asymm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "asymmetric"
      [[ -n "${LATEST_PUB_BASENAME:-}" ]] && set_config_value "$cfg" "pub_key_path" "crypto/asymm/server/${LATEST_PUB_BASENAME}"
      [[ -n "${LATEST_PR_BASENAME:-}"  ]] && set_config_value "$cfg" "pr_key_path"  "crypto/asymm/server/${LATEST_PR_BASENAME}"
      remove_config_key "$cfg" "sym_key_path"
      ;;
    symm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "symmetric"
      [[ -n "${LATEST_SYM_BASENAME:-}" ]] && set_config_value "$cfg" "sym_key_path" "crypto/symm/${LATEST_SYM_BASENAME}"
      remove_config_key "$cfg" "pub_key_path"
      remove_config_key "$cfg" "pr_key_path"
      ;;
    no)
      grep -Eq '^[[:space:]]*\[crypto\][[:space:]]*$' "$cfg"  && rename_ini_section "$cfg" "crypto" "inactive" || true
      grep -Eq '^[[:space:]]*\[removed\][[:space:]]*$' "$cfg" && rename_ini_section "$cfg" "removed" "inactive" || true
      ;;
  esac
}

update_root_filesend_config() {
  [[ -f "$ROOT_FILESEND_CONFIG" ]] || die "Missing root filesend_config: $ROOT_FILESEND_CONFIG"

  [[ -n "${LATEST_CA_BASENAME:-}" ]] \
    && set_config_value "$ROOT_FILESEND_CONFIG" "cert_path" "crypto/asymm/CA/${LATEST_CA_BASENAME}" \
    || warn "No CA cert available for root filesend_config"

  apply_encrypt_mode_to_root_config "$ROOT_FILESEND_CONFIG"
  set_config_value "$ROOT_FILESEND_CONFIG" "use_ws" "$([[ "$CONN_MODE" == "ws" ]] && echo true || echo false)"
  set_config_value "$ROOT_FILESEND_CONFIG" "url" "$CONN_URL"
}

update_generated_server_config() {
  [[ -f "$SERVER_CONFIG_PATH" ]] || die "Missing generated server config: $SERVER_CONFIG_PATH"

  set_config_value "$SERVER_CONFIG_PATH" "host" "$SERVER_HOST"
  set_config_value "$SERVER_CONFIG_PATH" "port" "$SERVER_PORT"
  [[ -n "${LATEST_SERVER_CERT_BASENAME:-}" ]] && set_config_value "$SERVER_CONFIG_PATH" "cert_path" "../crypto/asymm/server/${LATEST_SERVER_CERT_BASENAME}"
  [[ -n "${LATEST_SERVER_KEY_BASENAME:-}"  ]] && set_config_value "$SERVER_CONFIG_PATH" "key_path"  "../crypto/asymm/server/${LATEST_SERVER_KEY_BASENAME}"
}

apply_encrypt_mode_to_device_config() {
  local cfg="$1" device_id="$2" device_dir="$3"

  case "$ENCRYPT_MODE" in
    asymm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "asymmetric"
      if [[ -n "${LATEST_PUB_BASENAME:-}" && -f "$SERVER_CRYPTO_DIR/$LATEST_PUB_BASENAME" ]]; then
        cp "$SERVER_CRYPTO_DIR/$LATEST_PUB_BASENAME" "$device_dir/"
        set_config_value "$cfg" "pub_key_path" "$LATEST_PUB_BASENAME"
      else
        warn "No public key available for device $device_id"
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
        warn "No symmetric key available for device $device_id"
      fi
      remove_config_key "$cfg" "pub_key_path"
      remove_config_key "$cfg" "pr_key_path"
      ;;
    no)
      grep -Eq '^[[:space:]]*\[crypto\][[:space:]]*$' "$cfg"  && rename_ini_section "$cfg" "crypto" "inactive" || true
      grep -Eq '^[[:space:]]*\[removed\][[:space:]]*$' "$cfg" && rename_ini_section "$cfg" "removed" "inactive" || true
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
    warn "No CA cert available for device $device_id"
  fi

  apply_encrypt_mode_to_device_config "$device_cfg" "$device_id" "$device_dir"
  set_config_value "$device_cfg" "use_ws" "$([[ "$CONN_MODE" == "ws" ]] && echo true || echo false)"
  set_config_value "$device_cfg" "url" "$CONN_URL"
  set_config_value "$device_cfg" "device_id" "$device_id"

  log "Prepared device directory: $device_dir"
}

prepare_devices() {
  if should_force_devices; then
    log "Forcing rebuild of device directories"
    rm -rf "$DEVICES_ROOT"
    mkdir -p "$DEVICES_ROOT"
  fi

  for device_id in "${DEVICES[@]}"; do
    if [[ -d "$DEVICES_ROOT/$device_id" && ! should_force_devices ]]; then
      log "Reusing device directory: $DEVICES_ROOT/$device_id"
      continue
    fi
    prepare_device_dir "$device_id"
  done
}

resolve_container_incoming_dir() {
  local raw="$1"
  local abs_host

  [[ -d "$raw" ]] || die "Incoming directory not found: $raw"
  abs_host="$(cd "$raw" && pwd)"

  case "$abs_host" in
    "$APP_WORKSPACE_ABS")
      printf '/workspace\n'
      ;;
    "$APP_WORKSPACE_ABS"/*)
      printf '/workspace/%s\n' "${abs_host#"$APP_WORKSPACE_ABS"/}"
      ;;
    *)
      die "Incoming directory must live under app workspace: $APP_WORKSPACE_ABS"
      ;;
  esac
}

should_force_app() {
  [[ "$FORCE_MODE" == "all" ]] && return 0
  [[ "$MODE" == "--one" && "$FORCE_MODE" == "devices" ]] && return 0
  return 1
}

ensure_app_image() {
  if should_force_app || ! image_exists "$APP_IMAGE"; then
    docker_build "$APP_IMAGE" "$APP_DOCKERFILE" USER_ID GROUP_ID
  else
    log "Reusing existing app image: $APP_IMAGE"
  fi
}

run_app_send() {
  remove_container_if_exists "$APP_CONTAINER_NAME"

  local incoming_container_path
  incoming_container_path="$(resolve_container_incoming_dir "$INCOMING_DIR")"

  log "Running app container: $APP_CONTAINER_NAME"
  log "Command: filesend send $incoming_container_path"

  docker run --rm -it \
    --init \
    --name "$APP_CONTAINER_NAME" \
    --user "$(id -u):$(id -g)" \
    --network="$APP_NETWORK" \
    -v "$APP_WORKSPACE_ABS:/workspace" \
    -w /workspace \
    "$APP_IMAGE" \
    filesend send "$incoming_container_path"
}

print_summary() {
  cat <<EOF

Setup completed.

Repo root:
  $REPO_ROOT

Incoming directory:
  $INCOMING_DIR

Force mode:
  ${FORCE_MODE:-none}

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

Devices from config:
$(for d in "${DEVICES[@]}"; do printf '  - %s\n' "$d"; done)

EOF
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

  CONN_MODE_RAW="$(json_get "server_connection.mode")"
  CONN_URL_RAW="$(json_get "server_connection.url")"

  mapfile -t DEVICES < <(json_list_devices)

  SERVER_DOCKERFILE="${SERVER_DOCKERFILE:-Dockerfile.server}"
  SERVER_IMAGE="${SERVER_IMAGE:-filesend-server-dev}"
  SERVER_CONTAINER_NAME="${SERVER_CONTAINER_NAME:-filesend-server-dev}"
  SERVER_WORKSPACE_DIR="${SERVER_WORKSPACE_DIR:-server}"

  APP_DOCKERFILE="${APP_DOCKERFILE:-Dockerfile.sender}"
  APP_IMAGE="${APP_IMAGE:-filesend-app}"
  APP_CONTAINER_NAME="${APP_CONTAINER_NAME:-filesend-app}"
  APP_WORKSPACE_DIR="${APP_WORKSPACE_DIR:-.}"
  APP_NETWORK="${APP_NETWORK:-host}"

  CONN_MODE="$(normalize_connection_mode "${CONN_MODE_RAW:-ws}")"
  SERVER_MODE_ENV="${SERVER_MODE_ENV:-$CONN_MODE}"
  ENCRYPT_MODE="$(normalize_encrypt_mode "${APP_ENCRYPT_RAW:-asymm}")"

  SERVER_HOST="$(extract_host_from_url "${CONN_URL_RAW:-0.0.0.0}")"
  SERVER_PORT="$(extract_port_from_url "${CONN_URL_RAW:-0.0.0.0}" "$CONN_MODE")"
  CONN_URL="$(resolve_filesend_url "$CONN_MODE" "${CONN_URL_RAW:-0.0.0.0}")"
  SERVER_PORT_MAP="${SERVER_PORT_MAP:-${SERVER_PORT}:${SERVER_PORT}}"

  [[ ${#DEVICES[@]} -gt 0 ]] || die 'No devices found in config under "devices".'

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
  SERVER_REFRESHED="false"
}

print_resolved_config() {
  log "Resolved config:"
  log "  REPO_ROOT=$REPO_ROOT"
  log "  INCOMING_DIR=$INCOMING_DIR"
  log "  CONFIG_FILE=$CONFIG_FILE"
  log "  FORCE_MODE=${FORCE_MODE:-none}"
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
  log "  DEVICES_COUNT=${#DEVICES[@]}"
}

ensure_base_configs() {
  if should_force_all || [[ ! -f "$ROOT_FILESEND_CONFIG" || ! -f "$SERVER_CONFIG_PATH" ]]; then
    generate_base_configs
  else
    log "Reusing existing generated configs"
  fi
}

main() {
  parse_args "$@"
  load_config
  print_resolved_config

  ensure_base_configs
  ensure_server_available
  ensure_server_material
  update_root_filesend_config
  update_generated_server_config
  prepare_devices

  print_summary

  if [[ "$MODE" == "--multiple" ]]; then
    log "Multiple-node mode selected"
    log "The app container was not started by design"
    echo
    echo "To add a new device later, re-run:"
    echo "  ./$SCRIPT_NAME --multiple <incoming_directory> <config.json>"
    exit 0
  fi

  ensure_app_image
  run_app_send
}

main "$@"