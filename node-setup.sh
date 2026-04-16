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
  $SCRIPT_NAME <incoming_dir> [config.json] [--force[=all|server|devices]]
  $SCRIPT_NAME <incoming_dir> [config.json] --devices <id1,id2,...> [--force[=all|server|devices]]
  $SCRIPT_NAME <incoming_dir> [config.json] --add-device <id> [--force[=all|server|devices]]

Behavior:
  - Builds server/app images if needed
  - Generates base configs if needed
  - Generates or repairs security material by calling generate-security.sh
  - Prepares device directories only; does not run containers
  - Creates a per-device incoming directory:
      crypto/asymm/devices/<device_id>/<incoming_dir>

Selection:
  --devices <ids>       Prepare only the listed devices
  --add-device <id>     Prepare one new device without touching existing device material

Force options:
  --force               Same as --force=all
  --force=all           Rebuild everything
  --force=server        Rebuild images/base/server-side material
  --force=devices       Rebuild selected device directories only

Examples:
  $SCRIPT_NAME incoming
  $SCRIPT_NAME incoming setup.json --devices dev1,dev2
  $SCRIPT_NAME incoming setup.json --add-device dev3
  $SCRIPT_NAME incoming setup.json --force=devices
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

for cmd in docker python3 grep sed find cp mkdir chmod id rm; do
  require_cmd "$cmd"
done

INCOMING_DIR=""
CONFIG_FILE="setup.json"
FORCE_MODE=""
DEVICE_SELECTION_RAW=""
ADD_DEVICE_ID=""

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

CONN_MODE_RAW=""
CONN_URL_RAW=""

CONN_MODE=""
ENCRYPT_MODE=""
SERVER_HOST=""
SERVER_PORT=""
CONN_URL=""

SERVER_WORKSPACE_ABS=""
APP_WORKSPACE_ABS=""

GENERATE_CONFIGS_SCRIPT=""
GENERATE_SECURITY_SCRIPT=""
ROOT_FILESEND_CONFIG=""
SERVER_CONFIG_PATH=""

CRYPTO_ROOT=""
ASYMM_ROOT=""
SYMM_ROOT=""
SERVER_CRYPTO_DIR=""
DEVICES_ROOT=""
CA_DIR=""

LATEST_CA_BASENAME=""
LATEST_PUB_BASENAME=""
LATEST_SYM_BASENAME=""
LATEST_PR_BASENAME=""
LATEST_SERVER_CERT_BASENAME=""
LATEST_SERVER_KEY_BASENAME=""

DEVICES=()
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
      --force)
        FORCE_MODE="all"
        ;;
      --force=*)
        FORCE_MODE="${1#--force=}"
        ;;
      --devices)
        shift
        [[ $# -gt 0 ]] || die "--devices requires a value"
        DEVICE_SELECTION_RAW="$1"
        ;;
      --add-device)
        shift
        [[ $# -gt 0 ]] || die "--add-device requires a value"
        ADD_DEVICE_ID="$1"
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

  [[ -n "$INCOMING_DIR" ]] || die "Incoming directory must not be empty."
  [[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"

  case "$FORCE_MODE" in
    ""|all|server|devices) ;;
    *) die "Invalid --force value: $FORCE_MODE" ;;
  esac

  if [[ -n "$DEVICE_SELECTION_RAW" && -n "$ADD_DEVICE_ID" ]]; then
    die "Use either --devices or --add-device, not both."
  fi
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
    ""|ws|wss) printf '%s\n' "ws" ;;
    http|https) printf '%s\n' "http" ;;
    *) die "Unsupported server_connection.mode: $1" ;;
  esac
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
  local mode="$1" raw_url="$2"
  local host port

  host="$(extract_host_from_url "$raw_url")"
  port="$(extract_port_from_url "$raw_url" "$mode")"

  if [[ "$host" == *:* && "$host" != \[*\] ]]; then
    host="[$host]"
  fi

  case "$mode" in
    ws) printf '%s\n' "wss://${host}:${port}" ;;
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

ensure_base_configs() {
  if should_force_all || [[ ! -f "$ROOT_FILESEND_CONFIG" || ! -f "$SERVER_CONFIG_PATH" ]]; then
    generate_base_configs
  else
    log "Reusing existing generated configs"
  fi
}

ensure_server_images() {
  if should_force_server || ! image_exists "$SERVER_IMAGE"; then
    docker_build "$SERVER_IMAGE" "$SERVER_DOCKERFILE" USER_UID USER_GID
  else
    log "Reusing existing server image: $SERVER_IMAGE"
  fi

  if should_force_all || ! image_exists "$APP_IMAGE"; then
    docker_build "$APP_IMAGE" "$APP_DOCKERFILE" USER_ID GROUP_ID
  else
    log "Reusing existing app image: $APP_IMAGE"
  fi
}

ensure_security_material() {
  [[ -f "$GENERATE_SECURITY_SCRIPT" ]] || die "generate-security.sh not found: $GENERATE_SECURITY_SCRIPT"
  chmod +x "$GENERATE_SECURITY_SCRIPT"

  local gen_force=""
  if should_force_all || should_force_server; then
    gen_force="--force=all"
  fi

  log "Generating or repairing security material"
  (
    cd "$SERVER_WORKSPACE_ABS"
    if [[ -n "$gen_force" ]]; then
      "$GENERATE_SECURITY_SCRIPT" "$SERVER_WORKSPACE_ABS" "$gen_force"
    else
      "$GENERATE_SECURITY_SCRIPT" "$SERVER_WORKSPACE_ABS"
    fi
  )
}

load_existing_server_material_basenames() {
  LATEST_CA_BASENAME="$(find "$CA_DIR" -maxdepth 1 -type f -name 'ca_cert-*.pem' -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
  LATEST_PUB_BASENAME="$(find "$SERVER_CRYPTO_DIR" -maxdepth 1 -type f -name 'pub*.bin' -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
  LATEST_PR_BASENAME="$(find "$SERVER_CRYPTO_DIR" -maxdepth 1 -type f -name 'pr*.bin' -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
  LATEST_SERVER_CERT_BASENAME="$(find "$SERVER_CRYPTO_DIR" -maxdepth 1 -type f -name 'server-*.crt' -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
  LATEST_SERVER_KEY_BASENAME="$(find "$SERVER_CRYPTO_DIR" -maxdepth 1 -type f -name 'server-*.key' -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
  LATEST_SYM_BASENAME="$(find "$SYMM_ROOT" -maxdepth 1 -type f -name 'sym*.bin' -printf '%f\n' 2>/dev/null | sort | tail -n 1 || true)"
}

mirror_security_material_from_server_workspace() {
  local server_keys="$SERVER_WORKSPACE_ABS/keys"
  local server_certs="$SERVER_WORKSPACE_ABS/certs"

  mkdir -p "$CA_DIR" "$SERVER_CRYPTO_DIR" "$SYMM_ROOT"

  if compgen -G "$server_certs/ca_cert-*.pem" > /dev/null; then
    cp -f "$server_certs"/ca_cert-*.pem "$CA_DIR/" 2>/dev/null || true
  fi
  if compgen -G "$server_keys/pub*.bin" > /dev/null; then
    cp -f "$server_keys"/pub*.bin "$SERVER_CRYPTO_DIR/" 2>/dev/null || true
  fi
  if compgen -G "$server_keys/pr*.bin" > /dev/null; then
    cp -f "$server_keys"/pr*.bin "$SERVER_CRYPTO_DIR/" 2>/dev/null || true
  fi
  if compgen -G "$server_keys/sym*.bin" > /dev/null; then
    cp -f "$server_keys"/sym*.bin "$SYMM_ROOT/" 2>/dev/null || true
  fi
  if compgen -G "$server_keys/server-*.key" > /dev/null; then
    cp -f "$server_keys"/server-*.key "$SERVER_CRYPTO_DIR/" 2>/dev/null || true
  fi
  if compgen -G "$server_certs/server-*.crt" > /dev/null; then
    cp -f "$server_certs"/server-*.crt "$SERVER_CRYPTO_DIR/" 2>/dev/null || true
  fi
}

ensure_server_material() {
  mirror_security_material_from_server_workspace
  load_existing_server_material_basenames
  log "Using security material present on disk"
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

normalize_incoming_subpath() {
  local raw="$1"
  local clean="${raw#./}"
  clean="${clean#/}"
  clean="${clean%/}"
  [[ -n "$clean" ]] || die "Incoming directory must not be empty."
  [[ "$clean" != *".."* ]] || die "Incoming directory must not contain '..'"
  printf '%s\n' "$clean"
}

prepare_device_dir() {
  local device_id="$1"
  local incoming_subpath="$2"
  local device_dir="$DEVICES_ROOT/$device_id"
  local device_cfg="$device_dir/filesend_config"
  local device_incoming_dir="$device_dir/$incoming_subpath"

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

  mkdir -p "$device_incoming_dir"
  log "Prepared device directory: $device_dir"
  log "Prepared incoming directory: $device_incoming_dir"
}

resolve_selected_devices() {
  if [[ -n "$ADD_DEVICE_ID" ]]; then
    SELECTED_DEVICES=("$ADD_DEVICE_ID")
    return
  fi

  if [[ -n "$DEVICE_SELECTION_RAW" ]]; then
    IFS=',' read -r -a SELECTED_DEVICES <<< "$DEVICE_SELECTION_RAW"
    [[ ${#SELECTED_DEVICES[@]} -gt 0 ]] || die "No device ids parsed from --devices."
    return
  fi

  SELECTED_DEVICES=("${DEVICES[@]}")
}

prepare_devices() {
  local incoming_subpath="$1"

  if should_force_devices && [[ -z "$ADD_DEVICE_ID" ]]; then
    log "Forcing rebuild of selected device directories"
    for device_id in "${SELECTED_DEVICES[@]}"; do
      rm -r "$DEVICES_ROOT/$device_id"
    done
  fi

  for device_id in "${SELECTED_DEVICES[@]}"; do
    [[ -n "$device_id" ]] || continue

    if [[ -d "$DEVICES_ROOT/$device_id" && ! should_force_devices ]]; then
      if [[ -n "$ADD_DEVICE_ID" ]]; then
        log "Device already exists and will be left untouched: $device_id"
        mkdir -p "$DEVICES_ROOT/$device_id/$incoming_subpath"
        continue
      fi
      log "Reusing device directory: $DEVICES_ROOT/$device_id"
      mkdir -p "$DEVICES_ROOT/$device_id/$incoming_subpath"
      continue
    fi

    prepare_device_dir "$device_id" "$incoming_subpath"
  done
}

print_summary() {
  cat <<EOF

Setup completed.

Repo root:
  $REPO_ROOT

Incoming directory name:
  $INCOMING_DIR

Force mode:
  ${FORCE_MODE:-none}

Server image:
  $SERVER_IMAGE

App image:
  $APP_IMAGE

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

Prepared devices:
$(for d in "${SELECTED_DEVICES[@]}"; do printf '  - %s\n' "$d"; done)

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

  [[ ${#DEVICES[@]} -gt 0 ]] || warn 'No devices found in config under "devices".'

  REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
  SERVER_WORKSPACE_ABS="$(cd "$REPO_ROOT/$SERVER_WORKSPACE_DIR" && pwd)"
  APP_WORKSPACE_ABS="$(cd "$REPO_ROOT/$APP_WORKSPACE_DIR" && pwd)"

  GENERATE_CONFIGS_SCRIPT="$REPO_ROOT/generate-configs.sh"
  GENERATE_SECURITY_SCRIPT="$REPO_ROOT/generate-security.sh"
  ROOT_FILESEND_CONFIG="$REPO_ROOT/filesend_config"
  SERVER_CONFIG_PATH="$REPO_ROOT/server/server_config"

  CRYPTO_ROOT="$REPO_ROOT/crypto"
  ASYMM_ROOT="$CRYPTO_ROOT/asymm"
  SYMM_ROOT="$CRYPTO_ROOT/symm"
  SERVER_CRYPTO_DIR="$ASYMM_ROOT/server"
  DEVICES_ROOT="$ASYMM_ROOT/devices"
  CA_DIR="$ASYMM_ROOT/CA"

  mkdir -p "$SERVER_CRYPTO_DIR" "$DEVICES_ROOT" "$CA_DIR" "$SYMM_ROOT"
}

print_resolved_config() {
  log "Resolved config:"
  log "  REPO_ROOT=$REPO_ROOT"
  log "  INCOMING_DIR=$INCOMING_DIR"
  log "  CONFIG_FILE=$CONFIG_FILE"
  log "  FORCE_MODE=${FORCE_MODE:-none}"
  log "  SERVER_IMAGE=$SERVER_IMAGE"
  log "  APP_IMAGE=$APP_IMAGE"
  log "  ENCRYPT_MODE=$ENCRYPT_MODE"
  log "  CONN_MODE=$CONN_MODE"
  log "  SERVER_HOST=$SERVER_HOST"
  log "  SERVER_PORT=$SERVER_PORT"
  log "  CONN_URL=$CONN_URL"
}

main() {
  parse_args "$@"
  load_config
  resolve_selected_devices
  print_resolved_config

  local incoming_subpath
  incoming_subpath="$(normalize_incoming_subpath "$INCOMING_DIR")"

  ensure_base_configs
  ensure_server_images
  ensure_security_material
  ensure_server_material
  update_root_filesend_config
  update_generated_server_config
  prepare_devices "$incoming_subpath"

  print_summary
}

main "$@"