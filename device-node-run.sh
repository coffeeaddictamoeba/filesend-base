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
  $SCRIPT_NAME [--json <config.json>] --devices <id1,id2,...>
  $SCRIPT_NAME [--json <config.json>] --add-device <id>

Behavior:
  - Runs one app container per selected device
  - Uses incoming_dir from JSON config
  - Runs app containers from:
      crypto/<mode>/devices/<device_id>/<incoming_dir>

Defaults:
  --json setup.json

Notes:
  - Devices and security material should already be prepared by setup
  - --add-device can also create a missing device directory from the prepared
    runtime/security material, then start its container
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

for cmd in docker python3 grep sed id mkdir cp pwd dirname basename find; do
  require_cmd "$cmd"
done

CONFIG_FILE="setup.json"
DEVICE_SELECTION_RAW=""
ADD_DEVICE_ID=""

REPO_ROOT=""
APP_IMAGE=""
APP_CONTAINER_NAME=""
APP_NETWORK=""
APP_ENCRYPT_RAW=""

CONN_MODE_RAW=""
CONN_URL_RAW=""
INCOMING_DIR=""

ENCRYPT_MODE=""
CONN_MODE=""
CONN_URL=""
MODE_CRYPTO_ROOT=""
MODE_CRYPTO_REL=""
DEVICES_ROOT=""
SERVER_RUNTIME_DIR=""
CA_DIR=""
ROOT_FILESEND_CONFIG=""

SELECTED_DEVICES=()

ACTIVE_CA_SRC=""
ACTIVE_CA_BASENAME=""
ACTIVE_PUB_SRC=""
ACTIVE_PUB_BASENAME=""
ACTIVE_SYM_SRC=""
ACTIVE_SYM_BASENAME=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --json)
        shift
        [[ $# -gt 0 ]] || die "--json requires a value"
        CONFIG_FILE="$1"
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
  [[ -n "$DEVICE_SELECTION_RAW" || -n "$ADD_DEVICE_ID" ]] || die "Use --devices or --add-device"
  [[ -z "$DEVICE_SELECTION_RAW" || -z "$ADD_DEVICE_ID" ]] || die "Use either --devices or --add-device, not both."
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

normalize_connection_mode() {
  local mode
  mode="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    ""|ws|wss) printf '%s\n' "ws" ;;
    http|https) printf '%s\n' "http" ;;
    *) die "Unsupported server_connection.mode: $1" ;;
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
    ws)   printf '%s\n' "wss://${host}:${port}" ;;
    http) printf '%s\n' "https://${host}:${port}/upload" ;;
    *) die "Cannot resolve filesend URL for mode: $mode" ;;
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

copy_active_file_if_present() {
  local src="$1" dst_dir="$2"
  [[ -n "$src" ]] || return 0
  [[ -f "$src" ]] || die "Missing source file: $src"
  mkdir -p "$dst_dir"
  cp -f "$src" "$dst_dir/"
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
  if [[ -n "$ADD_DEVICE_ID" ]]; then
    SELECTED_DEVICES=("$ADD_DEVICE_ID")
  else
    IFS=',' read -r -a SELECTED_DEVICES <<< "$DEVICE_SELECTION_RAW"
    [[ ${#SELECTED_DEVICES[@]} -gt 0 ]] || die "No device ids parsed from --devices."
  fi
}

load_config() {
  REPO_ROOT="$(json_get "repo_root")"
  REPO_ROOT="${REPO_ROOT:-.}"

  INCOMING_DIR="$(json_get "incoming_dir")"
  [[ -n "$INCOMING_DIR" ]] || die "Missing required JSON key: incoming_dir"

  APP_IMAGE="$(json_get "app.image")"
  APP_CONTAINER_NAME="$(json_get "app.container_name")"
  APP_NETWORK="$(json_get "app.network")"
  APP_ENCRYPT_RAW="$(json_get "app.encrypt")"

  CONN_MODE_RAW="$(json_get "server_connection.mode")"
  CONN_URL_RAW="$(json_get "server_connection.url")"

  APP_IMAGE="${APP_IMAGE:-filesend-app}"
  APP_CONTAINER_NAME="${APP_CONTAINER_NAME:-filesend-app}"
  APP_NETWORK="${APP_NETWORK:-host}"

  ENCRYPT_MODE="$(normalize_encrypt_mode "${APP_ENCRYPT_RAW:-asymm}")"
  CONN_MODE="$(normalize_connection_mode "${CONN_MODE_RAW:-ws}")"
  CONN_URL="$(resolve_filesend_url "$CONN_MODE" "${CONN_URL_RAW:-0.0.0.0}")"

  REPO_ROOT="$(cd "$REPO_ROOT" && pwd -P)"

  case "$ENCRYPT_MODE" in
    symm)
      MODE_CRYPTO_ROOT="$REPO_ROOT/crypto/symm"
      MODE_CRYPTO_REL="crypto/symm"
      ;;
    asymm|no)
      MODE_CRYPTO_ROOT="$REPO_ROOT/crypto/asymm"
      MODE_CRYPTO_REL="crypto/asymm"
      ;;
  esac

  SERVER_RUNTIME_DIR="$MODE_CRYPTO_ROOT/server"
  DEVICES_ROOT="$MODE_CRYPTO_ROOT/devices"
  CA_DIR="$MODE_CRYPTO_ROOT/CA"
  ROOT_FILESEND_CONFIG="$REPO_ROOT/filesend_config"
}

ensure_runtime_material() {
  [[ -d "$SERVER_RUNTIME_DIR" ]] || die "Prepared server runtime dir not found: $SERVER_RUNTIME_DIR"
  [[ -f "$ROOT_FILESEND_CONFIG" ]] || die "Root filesend_config not found: $ROOT_FILESEND_CONFIG"
}

select_runtime_security_material() {
  ensure_runtime_material

  local ca_file=""
  ca_file="$(find "$SERVER_RUNTIME_DIR/certs" -maxdepth 1 -type f -name 'ca_cert-*.pem' | sort | tail -n 1 || true)"
  [[ -n "$ca_file" ]] || die "No CA certificate found in $SERVER_RUNTIME_DIR/certs"

  ACTIVE_CA_SRC="$ca_file"
  ACTIVE_CA_BASENAME="$(basename "$ACTIVE_CA_SRC")"

  ACTIVE_PUB_SRC=""
  ACTIVE_PUB_BASENAME=""
  ACTIVE_SYM_SRC=""
  ACTIVE_SYM_BASENAME=""

  case "$ENCRYPT_MODE" in
    asymm)
      ACTIVE_PUB_SRC="$(find "$SERVER_RUNTIME_DIR/keys" -maxdepth 1 -type f -name 'pub_key-*.bin' | sort | tail -n 1 || true)"
      [[ -n "$ACTIVE_PUB_SRC" ]] || die "No public key found in $SERVER_RUNTIME_DIR/keys"
      ACTIVE_PUB_BASENAME="$(basename "$ACTIVE_PUB_SRC")"
      ;;
    symm)
      ACTIVE_SYM_SRC="$(find "$SERVER_RUNTIME_DIR/keys" -maxdepth 1 -type f -name 'sym_key-*.bin' | sort | tail -n 1 || true)"
      [[ -n "$ACTIVE_SYM_SRC" ]] || die "No symmetric key found in $SERVER_RUNTIME_DIR/keys"
      ACTIVE_SYM_BASENAME="$(basename "$ACTIVE_SYM_SRC")"
      ;;
  esac
}

apply_encrypt_mode_to_config() {
  local cfg="$1" device_dir="$2"

  case "$ENCRYPT_MODE" in
    asymm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "asymmetric"
      copy_active_file_if_present "$ACTIVE_PUB_SRC" "$device_dir"
      set_config_value "$cfg" "pub_key_path" "$ACTIVE_PUB_BASENAME"
      remove_config_key "$cfg" "pr_key_path"
      remove_config_key "$cfg" "sym_key_path"
      ;;
    symm)
      ensure_ini_section_name "$cfg" "crypto"
      set_config_value "$cfg" "mode" "symmetric"
      copy_active_file_if_present "$ACTIVE_SYM_SRC" "$device_dir"
      set_config_value "$cfg" "sym_key_path" "$ACTIVE_SYM_BASENAME"
      remove_config_key "$cfg" "pub_key_path"
      remove_config_key "$cfg" "pr_key_path"
      ;;
    no)
      grep -Eq '^[[:space:]]*\[crypto\][[:space:]]*$' "$cfg"  && rename_ini_section "$cfg" "crypto" "inactive" || true
      grep -Eq '^[[:space:]]*\[removed\][[:space:]]*$' "$cfg" && rename_ini_section "$cfg" "removed" "inactive" || true
      remove_config_key "$cfg" "pub_key_path"
      remove_config_key "$cfg" "pr_key_path"
      remove_config_key "$cfg" "sym_key_path"
      ;;
  esac
}

ensure_device_dir_exists() {
  local device_id="$1"
  local incoming_subpath="$2"
  local device_dir="$DEVICES_ROOT/$device_id"
  local device_cfg="$device_dir/filesend_config"

  [[ -d "$device_dir" ]] || die "Device directory not found: $device_dir"
  [[ -f "$device_cfg" ]] || die "Missing device config: $device_cfg"
  [[ -d "$device_dir/$incoming_subpath" ]] || die "Missing device incoming dir: $device_dir/$incoming_subpath"
}

ensure_app_image() {
  if ! image_exists "$APP_IMAGE"; then
    die "App image not found: $APP_IMAGE. Build it first with your setup flow."
  fi
  log "Reusing existing app image: $APP_IMAGE"
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

  if container_running "$container_name"; then
    log "App container already running for device: $device_id"
    return
  fi

  if container_exists "$container_name"; then
    log "Removing stopped existing container: $container_name"
    docker rm -f "$container_name" >/dev/null
  fi

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

Node run started.

Crypto mode:
  $ENCRYPT_MODE

Incoming directory name:
  $INCOMING_DIR

Selected devices:
$(for d in "${SELECTED_DEVICES[@]}"; do printf '  - %s\n' "$d"; done)

EOF
}

main() {
  parse_args "$@"
  load_config
  resolve_selected_devices

  local incoming_subpath
  incoming_subpath="$(normalize_incoming_subpath "$INCOMING_DIR")"

  ensure_app_image

  for device_id in "${SELECTED_DEVICES[@]}"; do
    ensure_device_dir_exists "$device_id" "$incoming_subpath"
    run_app_for_device "$device_id" "$incoming_subpath"
  done

  print_summary
}

main "$@"